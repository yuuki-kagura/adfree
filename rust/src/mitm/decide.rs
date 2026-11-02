//! The filter decisions themselves, independent of the protocol that carries
//! the request.
//!
//! HTTPS/1.1 reaches this module through a raw head in a byte buffer; HTTP/3
//! serializes its pseudo-headers and headers into the same shape and reads the
//! result back. Everything here is bytes in, decision out: no sockets, no TLS
//! connections, no client-facing framing.

use std::sync::Arc;

use crate::filter::{CookiePlan, FilterEngine, HlsPlan, HtmlPlan, JsonprunePlan, Replace};

use super::http;
use super::proxy::{
    blocked_response, closing_response, content_hash, escape_for_script, header_end,
    hide_stylesheet, local_asset, origin_form, rebuilt_head, redirect_response, rewritable,
    transform_redirect_response, versioned_path, PAGE_RUNTIME, PAGE_SCRIPT_PATH,
};

/// What one forwarded request carries back from the filter: the response body
/// rewrite it matched, if any, and the header edits its response needs.
#[derive(Default)]
pub(crate) struct RequestPlan {
    /// The `$replace` rule: its response body is rewritten when it comes back.
    pub(crate) replace: Option<Arc<Replace>>,
    /// Header edits, computed once, here, and held until the response arrives.
    pub(crate) headers: Option<Arc<crate::filter::HeaderEdit>>,
    /// The `$cookie` rules the request matched: the request loses the cookies
    /// they name now, and the response may not set them — the same plan
    /// answers both, so it rides along.
    pub(crate) cookies: Option<Arc<CookiePlan>>,
    /// Stealth mode: the request is cross-site, so its `Cookie` header went
    /// away and the answer may not set new ones.
    pub(crate) block_cookies: bool,
    /// Stealth mode: `ETag` is a stable identifier for this client's cache, so
    /// the request lost its conditional headers and the answer may not set a
    /// new tag either.
    pub(crate) drop_etag: bool,
    /// The `$jsonprune` rules the request matched: held until the response
    /// body arrives.
    pub(crate) jsonprune: Option<Arc<JsonprunePlan>>,
    /// The `$hls` rules the request matched: held until the response body
    /// arrives.
    pub(crate) hls: Option<Arc<HlsPlan>>,
    /// The `$$` / `##^` HTML filtering rules the request matched: held until
    /// the response body arrives.
    pub(crate) html: Option<Arc<HtmlPlan>>,
    /// The request's page URL when the loaded lists carry `[$path=…]` rules:
    /// what the injection matches those rules against. Rides on the plan so
    /// the response edit — which happens long after the head was read — can
    /// find it again.
    pub(crate) page_url: Option<String>,
}

/// A locally served answer a rule decided on.
pub(crate) struct Answer {
    /// The complete HTTP/1.1 response, ready for either transport: HTTP/3
    /// parses its status and headers back into its own response.
    pub(crate) response: Vec<u8>,
    pub(crate) rule: Option<String>,
    pub(crate) list_name: Option<String>,
    pub(crate) category: u8,
}

pub(crate) struct Decision {
    pub(crate) plan: RequestPlan,
    /// The end of the (possibly edited) head in the request buffer.
    pub(crate) head_end: usize,
    /// Set when the request must not reach the origin.
    pub(crate) answer: Option<Answer>,
}

/// Everything the rules need from one request, already parsed out of the head.
pub(crate) struct RequestContext<'a> {
    pub(crate) filter: &'a FilterEngine,
    pub(crate) host: &'a str,
    pub(crate) url: &'a str,
    pub(crate) method: &'a str,
    pub(crate) target: &'a str,
    pub(crate) source: &'a str,
    pub(crate) request_type: &'a str,
    pub(crate) apps: &'a [String],
    pub(crate) page_url: Option<String>,
    pub(crate) closes: bool,
}

/// Runs every URL-level rule on one request head.
///
/// The head may be edited in place: `$removeheader` drops request headers,
/// `$urltransform`/`$removeparam` rewrite the request line, and `$cookie`
/// takes cookies off. `head_end` is returned because each edit moves it.
pub(crate) fn decide_request(
    ctx: &RequestContext<'_>,
    head: &mut Vec<u8>,
    mut head_end: usize,
) -> Decision {
    let filter = ctx.filter;
    let host = ctx.host;
    let url = ctx.url;
    let source = ctx.source;
    let method = ctx.method;
    let target = ctx.target;
    let request_type = ctx.request_type;
    let apps = ctx.apps;
    let closes = ctx.closes;

    // `$urlblock` (and `$document`, which implies it): the page asked for
    // its own requests not to be blocked. The page is the document itself,
    // or the referrer of a subresource. AdGuard spells the coverage out —
    // blocking, redirects *and* `$removeparam` — so the whole decision is
    // skipped for such a page.
    let page_host = if request_type == "document" {
        crate::filter::url_host(url)
    } else {
        crate::filter::url_host(source)
    };
    if !page_host.is_empty() && filter.cosmetic_switches_for(page_host).urlblock {
        // The network decision is skipped, but the page's cosmetics still
        // run: `$urlblock` alone unblocks requests, it does not switch
        // element hiding off.
        return Decision {
            plan: RequestPlan {
                page_url: ctx.page_url.clone(),
                ..RequestPlan::default()
            },
            head_end,
            answer: None,
        };
    }

    // The response-header rules (`$csp`, `$permissions`, `$removeheader`)
    // are matched once, here, and ride on the plan: the response they shape
    // is the next thing to come back. The request-side half of
    // `$removeheader` happens now, while the head is here — the rest waits.
    let mut plan = RequestPlan {
        page_url: ctx.page_url.clone(),
        ..RequestPlan::default()
    };
    if filter.has_header_rules() {
        if let Some(edit) = filter.header_edit(url, source, request_type, method) {
            // `drop_headers` is `None` when none of the names is there, so
            // the request is spliced only when it actually changes.
            if let Some(fixed) = http::drop_headers(&head[..head_end], &edit.remove_request) {
                let old_end = head_end;
                head_end = fixed.len();
                head.splice(..old_end, fixed);
                crate::logbuf::push(&format!(
                    "mitm {host}: request headers dropped: {}",
                    edit.remove_request.join(", ")
                ));
            }
            plan.headers = Some(Arc::new(edit));
        }
    }

    // `$jsonprune`: the response body loses the JSON items the matching
    // rules name. Matched here, like the header edits, and held until the
    // body comes back; a request that ends up blocked discards the plan
    // with its answer, and the page's own switches were asked above
    // (`$urlblock`) and inside the finder (`$content`, an empty
    // `$replace`).
    if filter.has_jsonprune_rules() {
        if let Some(rules) = filter.jsonprune_plan(url, source, request_type, method) {
            plan.jsonprune = Some(Arc::new(rules));
        }
    }

    // `$hls`: the response playlist loses the segments the matching rules
    // name, media playlists and master playlists alike. Matched here like
    // the other body edits, held until the body comes back; a blocked
    // request discards the plan with its answer.
    if filter.has_hls_rules() {
        if let Some(rules) = filter.hls_plan(url, source, request_type, method) {
            plan.hls = Some(Arc::new(rules));
        }
    }

    // `$$` / `##^`: the response body loses the elements the matching
    // rules name. Matched here like the other body edits and held until
    // the body comes back; the body pipeline runs it after `$jsonprune`
    // and before `$replace`.
    if filter.has_html_rules() {
        if let Some(rules) = filter.html_plan_for_apps(url, source, request_type, apps) {
            plan.html = Some(rules);
        }
    }

    // `$replace`: the response body is rewritten *instead of* the request
    // being blocked — AdGuard gives the modifier priority over every other
    // basic rule, so a URL it matches is never blocked. The request goes
    // out untouched; the response is picked up again when it comes back.
    if filter.has_replace() {
        if let Some(rule) = filter.replace_for(url, source, request_type, method) {
            plan.replace = Some(rule);
            apply_cookie_plan(filter, head, head_end, url, source, method, host, &mut plan);
            return Decision {
                plan,
                head_end,
                answer: None,
            };
        }
    }

    let mut verdict = filter.check_url(url, source, request_type, method, apps);
    if !verdict.blocked {
        // The request-URL modifiers. `$urltransform` and the shapes of
        // `$removeparam` the crate refuses are run by our own engine here;
        // the `=name` shape the crate does implement comes back on the
        // verdict itself. AdGuard keeps `$urltransform` out of the way of a
        // URL basic rules already block, so this only runs on a clear
        // verdict.
        let mut rewritten_target: Option<String> = None;
        let mut transformed: Option<crate::filter::UrlEdit> = None;
        if filter.has_url_rules() {
            if let Some(edit) = filter.url_edit(url, source, request_type, method) {
                if !crate::filter::same_origin(url, &edit.url) {
                    // The rule reaches for another origin, which no rewrite
                    // of the request line can take the request to — but a
                    // redirect can, and only a method that allows one may
                    // be answered that way.
                    if matches!(method, "GET" | "HEAD") {
                        let rules = edit.rules.join("; ");
                        crate::logbuf::push(&format!(
                            "mitm {host}: URL transform redirects to {} ({rules})",
                            edit.url
                        ));
                        let mut response = transform_redirect_response(&edit.url);
                        if closes {
                            response = closing_response(response);
                        }
                        return Decision {
                            plan: RequestPlan::default(),
                            head_end,
                            answer: Some(Answer {
                                response,
                                rule: Some(rules),
                                list_name: None,
                                category: 0,
                            }),
                        };
                    }
                } else if rewritable(method) {
                    if let Some(new_target) = origin_form(&edit.url) {
                        if new_target != target {
                            // The transformed URL is a request of its own:
                            // it is matched against the rest of the rules
                            // before it goes out.
                            verdict =
                                filter.check_url(&edit.url, source, request_type, method, apps);
                            if !verdict.blocked {
                                rewritten_target = Some(new_target);
                                transformed = Some(edit);
                            }
                        }
                    }
                }
            }
        } else if let Some(rewritten) = verdict
            .rewritten_url
            .as_deref()
            .filter(|_| rewritable(method))
        {
            // A `$removeparam` rule the crate implements itself: the
            // request still goes out, with the parameters the list dropped
            // taken off. GET, HEAD, OPTIONS and POST — see [`rewritable`]
            // — so anything else keeps its query.
            if let Some(new_target) = origin_form(rewritten) {
                if new_target != target {
                    rewritten_target = Some(new_target);
                }
            }
        }
        if !verdict.blocked {
            if let Some(rewritten_target) = rewritten_target {
                // The rebuilt line is as long as the target it carries, so
                // the head end moves with it: the cookie plan below (and
                // the plan's own record) reads the head that actually goes
                // out, and the old end would slice past its end whenever
                // the rewrite is shorter.
                let old_end = head_end;
                let rebuilt = rebuilt_head(&head[..old_end], &rewritten_target);
                head_end = rebuilt.len();
                head.splice(..old_end, rebuilt);
                if let Some(edit) = transformed {
                    crate::logbuf::push(&format!(
                        "mitm {host}: URL rewritten to {} by {} rule(s)",
                        edit.url,
                        edit.rules.len(),
                    ));
                }
            }
            apply_cookie_plan(filter, head, head_end, url, source, method, host, &mut plan);
            return Decision {
                plan,
                head_end,
                answer: None,
            };
        }
    }

    let mut response = verdict
        .redirect
        .as_deref()
        .and_then(redirect_response)
        .unwrap_or_else(blocked_response);
    if method == "HEAD" {
        // A HEAD answer is headers only. The length of the body the same
        // request would have carried is already in the head, so dropping
        // the bytes is all it takes.
        if let Some(end) = header_end(&response) {
            response.truncate(end);
        }
    }
    if closes {
        response = closing_response(response);
    }
    Decision {
        plan: RequestPlan::default(),
        head_end,
        answer: Some(Answer {
            response,
            rule: verdict.rule_text.clone(),
            list_name: verdict.list_name.clone(),
            category: verdict.category,
        }),
    }
}

/// Applies the `$cookie` plan to the request head at the front of `head`:
/// the cookies the rules name come off the `Cookie` header, and the plan
/// rides on `plan` so the response that request produces cannot set them
/// either.
///
/// The rules are matched against the URL the client sent — the way the
/// reference reads its matching result — so a request a `$urltransform`
/// rewrote is still the exchange that client meant to make.
#[allow(clippy::too_many_arguments)]
fn apply_cookie_plan(
    filter: &FilterEngine,
    head: &mut Vec<u8>,
    head_end: usize,
    url: &str,
    source: &str,
    method: &str,
    host: &str,
    plan: &mut RequestPlan,
) {
    if !filter.has_cookie_rules() {
        return;
    }
    let Some(cookie_plan) = filter.cookie_plan(url, source, method) else {
        return;
    };
    let names = http::request_cookie_names(&head[..head_end]);
    if !names.is_empty() {
        if let Some(edit) = cookie_plan.dropped(&names) {
            // `drop_request_cookies` is `None` when none of the names is
            // there, so the request is spliced only when it really changes.
            if let Some(fixed) = http::drop_request_cookies(&head[..head_end], &edit.drop) {
                let old_end = head_end;
                head.splice(..old_end, fixed);
                crate::logbuf::push(&format!(
                    "mitm {host}: request cookies dropped: {} by {} rule(s)",
                    edit.drop.join(", "),
                    edit.rules.len(),
                ));
            }
        }
    }
    plan.cookies = Some(Arc::new(cookie_plan));
}

/// What the response body pipeline needs to know about the plans a request
/// matched.
#[derive(Default)]
pub(crate) struct ResponsePlans {
    pub(crate) replace: Option<Arc<Replace>>,
    pub(crate) jsonprune: Option<Arc<JsonprunePlan>>,
    pub(crate) hls: Option<Arc<HlsPlan>>,
    pub(crate) html: Option<Arc<HtmlPlan>>,
}

pub(crate) struct EditedBody {
    pub(crate) body: Vec<u8>,
    /// Bytes the snippet added.
    pub(crate) injected: usize,
    /// A rule changed the body, with or without an injection.
    pub(crate) edited: bool,
    pub(crate) decision: http::Decision,
    /// The nonce this response's tags carry; the head policy learns it when a
    /// snippet goes out.
    pub(crate) nonce: String,
}

/// Applies the body-editing rules to one decoded response body.
///
/// Order is the contract: `$hls`, `$jsonprune`, `$$`, `$replace`, and the
/// injected snippet last — each pass reads what the previous one left.
pub(crate) fn edit_response(
    plans: &ResponsePlans,
    plain: &[u8],
    inject: bool,
    injector: &Injector<'_>,
    host: &str,
) -> EditedBody {
    // `$hls` first: the playlist edit drops whole lines, and the passes below
    // read what it left. Each log line names the bytes its own pass started
    // from.
    let original = plain.len();
    let trimmed = plans.hls.as_ref().and_then(|plan| plan.apply(plain));
    let plain = trimmed
        .as_ref()
        .map(|(body, _)| body.as_slice())
        .unwrap_or(plain);
    if let Some((_, applied)) = trimmed.as_ref() {
        crate::logbuf::push(&format!(
            "mitm {host}: $hls applied ({} to {} bytes): {}",
            original,
            plain.len(),
            applied.join("; "),
        ));
    }
    // `$jsonprune` takes its matches out of the document itself, and the
    // `$replace` pass below then reads the pruned bytes — a regexp written for
    // what the client will get.
    let before_prune = plain.len();
    let pruned = plans.jsonprune.as_ref().and_then(|plan| plan.apply(plain));
    let plain = pruned
        .as_ref()
        .map(|(body, _)| body.as_slice())
        .unwrap_or(plain);
    if let Some((_, applied)) = pruned.as_ref() {
        crate::logbuf::push(&format!(
            "mitm {host}: $jsonprune applied ({} to {} bytes): {}",
            before_prune,
            plain.len(),
            applied.join("; "),
        ));
    }
    // `$$` / `##^`: the elements the matching rules name are cut out of the
    // document itself, and the `$replace` pass below then reads what they
    // left — a regexp written for what the client will get.
    let before_html = plain.len();
    let cut = plans.html.as_ref().and_then(|plan| plan.apply(plain));
    let plain = cut
        .as_ref()
        .map(|(body, _)| body.as_slice())
        .unwrap_or(plain);
    if let Some((_, applied)) = cut.as_ref() {
        crate::logbuf::push(&format!(
            "mitm {host}: $$ applied ({} to {} bytes): {}",
            before_html,
            plain.len(),
            rules_summary(applied),
        ));
    }
    // `$replace` second: what a list rewrites is the page's own bytes, and
    // the snippet injected below is ours, not the list's — the two never feed
    // into one another.
    let before = plain.len();
    let replaced = plans.replace.as_ref().and_then(|rule| rule.apply(plain));
    let plain = replaced.as_deref().unwrap_or(plain);
    if let Some(rule) = plans.replace.as_ref().filter(|_| replaced.is_some()) {
        crate::logbuf::push(&format!(
            "mitm {host}: $replace applied ({} to {} bytes): {}",
            before,
            plain.len(),
            payload_summary(rule.payload())
        ));
    }
    let edited = replaced.is_some() || pruned.is_some() || trimmed.is_some() || cut.is_some();
    // One nonce for this response: the tags carry it, and the policy does too
    // when the head goes out rewritten below.
    let nonce = http::new_nonce();
    let snippet = if inject {
        injector.snippet(plain, &nonce)
    } else {
        Vec::new()
    };
    let (body, decision) = if snippet.is_empty() {
        (plain.to_vec(), http::Decision::Skip)
    } else {
        http::inject_snippet(plain, &snippet)
    };
    let injected = if decision == http::Decision::Injected {
        body.len().saturating_sub(plain.len())
    } else {
        0
    };
    EditedBody {
        body,
        injected,
        edited,
        decision,
        nonce,
    }
}

/// One `$replace` payload, short enough for a log line.
fn payload_summary(payload: &str) -> String {
    const MAX: usize = 96;
    if payload.chars().count() <= MAX {
        return payload.to_string();
    }
    let cut: String = payload.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

/// The text of the rules one response edit applied, short enough for a log
/// line: the rules as they come, cut on a character boundary when there are
/// too many or they are too long.
fn rules_summary(rules: &[String]) -> String {
    const MAX: usize = 160;
    let joined = rules.join("; ");
    if joined.chars().count() <= MAX {
        return joined;
    }
    let cut: String = joined.chars().take(MAX - 1).collect();
    format!("{cut}…")
}

/// The per-session inputs the injected snippet depends on.
pub(crate) struct Injector<'a> {
    pub(crate) script_src: &'a str,
    pub(crate) script_tag_src: &'a str,
    pub(crate) cosmetic: Option<&'a FilterEngine>,
    /// The hostname the connection was opened for.
    pub(crate) host: Option<&'a str>,
    pub(crate) page_url: Option<&'a str>,
    pub(crate) apps: &'a [String],
    pub(crate) stealth: crate::engine::StealthConfig,
}

impl Injector<'_> {
    /// Whether any of the three injection sources is in play; a connection
    /// that is here for header edits alone must not hold bodies back.
    pub(crate) fn active(&self) -> bool {
        !self.script_src.is_empty() || self.cosmetic.is_some() || self.stealth.injects_guards()
    }


    /// The HTML snippet injected early in `<head>`: the hiding stylesheet, the
    /// cosmetic payload (rule data inline, runtime fetched from the app's own
    /// origin) plus the user script tag when one is installed. Empty when
    /// nothing applies.
    ///
    /// Every tag carries `nonce`, and the head's policy is taught the same
    /// value before it leaves, so a strict `script-src`/`style-src` lets the
    /// snippet through without the page losing its policy.
    pub(crate) fn snippet(&self, body: &[u8], nonce: &str) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(filter) = self.cosmetic {
            let switches = self
                .host
                .map(|host| filter.cosmetic_switches_for(host))
                .unwrap_or_default();
            // A page the lists unblocked (`$document`, or `$elemhide` together
            // with `$jsinject`) has nothing left to hide, look up or inject:
            // every tag would be a fetch for nothing. The user's own script is
            // not the lists' to switch off, and still goes out below.
            if !(switches.elemhide && switches.jsinject) {
                // Without a hostname there are no rules to look up (a session
                // that never saw a ClientHello keeps only the runtime).
                if let Some(host) = self.host {
                    // What the rules hide goes out as a stylesheet, not as inline
                    // data: the same 11 KB of all-site selectors applies to every
                    // page of a site, and this way the browser fetches it once and
                    // keeps it. It is fetched from the app's own origin, where the
                    // page's service worker cannot answer in our place. A
                    // page-scoped `#@#` exception is the one case the host
                    // stylesheet cannot express: the caller below then carries
                    // the filtered selectors inline for this page only.
                    let payload =
                        self.cosmetic_payload(filter, host, body, self.page_url, self.apps);
                    let inline_hides = payload.as_ref().is_some_and(|page| page.inline_hides);
                    if !inline_hides {
                        if let Some((href, _)) = hide_stylesheet(filter, host) {
                            out.extend_from_slice(
                                http::style_link_tag(&local_asset(&href), "adfree-hide", nonce)
                                    .as_bytes(),
                            );
                        }
                    }
                    if let Some(data) = payload.and_then(|page| page.json) {
                        out.extend_from_slice(
                            format!("<script{}>window.__adfree_page=", http::nonce_attr(nonce))
                                .as_bytes(),
                        );
                        out.extend_from_slice(data.as_bytes());
                        out.extend_from_slice(b";</script>");
                    }
                }
                // The runtime goes out whenever cosmetic filtering runs, payload or
                // not: it is what finds rules for the tokens the proxy never saw,
                // which on a streamed page is everything past the anchor.
                // Not deferred: the hiding stylesheet must land before the body
                // renders, and every answer comes from the app itself.
                // `dmn=` is what tells the cross-origin runtime which host's rules
                // its lookups are for (AdGuard's content script carries the same
                // parameter).
                let runtime = match self.host {
                    Some(host) => versioned_path(
                        &format!("{PAGE_SCRIPT_PATH}?dmn={host}"),
                        content_hash(PAGE_RUNTIME.as_bytes()),
                    ),
                    None => versioned_path(PAGE_SCRIPT_PATH, content_hash(PAGE_RUNTIME.as_bytes())),
                };
                out.extend_from_slice(
                    http::script_tag(&local_asset(&runtime), false, nonce).as_bytes(),
                );
            }
        }
        for (on, guard) in [
            (self.stealth.blocks_web_rtc(), crate::mitm::stealth::WEBRTC_GUARD),
            (self.stealth.blocks_push_api(), crate::mitm::stealth::PUSH_GUARD),
            (
                self.stealth.blocks_geolocation_api(),
                crate::mitm::stealth::GEOLOCATION_GUARD,
            ),
        ] {
            if !on {
                continue;
            }
            // Inline rather than served: the guard is tiny and has to run
            // before the page's own scripts. The nonce keeps a strict
            // `script-src` from dropping it.
            out.extend_from_slice(
                format!("<script{}>{}</script>", http::nonce_attr(nonce), guard).as_bytes(),
            );
        }

        if !self.script_src.is_empty() {
            // Not deferred: `@run-at document-start` only means anything if
            // the tag is fetched and executed while the parser is still in the
            // head. End/idle scripts wait inside their own wrapper.
            out.extend_from_slice(http::script_tag(self.script_tag_src, false, nonce).as_bytes());
        }
        out
    }

    /// The per-page cosmetic payload as JSON, or `None` when the page has
    /// nothing left to carry inline (element hiding travels as a stylesheet).
    ///
    /// `page_url` is the page's own URL when the request carried one — that is
    /// what `[$path=…]` / `[$url=…]` / path-in-domain rules are matched
    /// against. Without it the answer is the host's alone: no `/`-path may
    /// stand in for a page nobody named.
    fn cosmetic_payload(
        &self,
        filter: &FilterEngine,
        host: &str,
        body: &[u8],
        page_url: Option<&str>,
        apps: &[String],
    ) -> Option<CosmeticPayload> {
        let rules = match page_url {
            Some(url) => filter.cosmetic_resources_with_apps(url, apps),
            None => filter.cosmetic_resources_for_host_with_apps(host, apps),
        };
        let inline_hides = rules.inline_hides;

        // Generic class/id rules: the page's own tokens decide which apply.
        // The initial HTML is scanned here so the first paint is covered; the
        // runtime asks again for whatever the page adds later.
        let mut generic = Vec::new();
        if !rules.generichide {
            let (classes, ids) = http::collect_class_id_tokens(body);
            if !classes.is_empty() || !ids.is_empty() {
                generic = filter.generic_selectors(&classes, &ids, &rules.exceptions);
            }
        }

        let mut obj = serde_json::Map::new();
        if inline_hides && !rules.hide_selectors.is_empty() {
            obj.insert("hide".into(), serde_json::json!(rules.hide_selectors));
        }
        if inline_hides && !rules.generichide {
            // The generic lookup endpoint is host-only and cannot see the
            // page scope. Carry the page's exceptions so the runtime can
            // drop a dynamic answer the exception already cancelled.
            obj.insert("exceptions".into(), serde_json::json!(rules.exceptions));
        }
        if !rules.style_rules.is_empty() {
            obj.insert("style".into(), serde_json::json!(rules.style_rules));
        }
        if !generic.is_empty() {
            obj.insert("generic".into(), serde_json::json!(generic));
        }
        if !rules.procedural.is_empty() {
            obj.insert("procedural".into(), serde_json::json!(rules.procedural));
        }
        if !rules.scriptlets.is_empty() {
            obj.insert("scriptlets".into(), serde_json::json!(rules.scriptlets));
        }
        if !rules.jsrules.is_empty() {
            obj.insert("jsrules".into(), serde_json::json!(rules.jsrules));
        }
        // With `$generichide` in play the dynamic lookup would answer `[]`
        // every time; say so, and only then — the runtime assumes it is on, so
        // a page whose payload never made it out still gets the lookup.
        if rules.generichide {
            obj.insert("dynamic".into(), serde_json::json!(false));
        }
        let json = if obj.is_empty() {
            None
        } else {
            Some(escape_for_script(
                &serde_json::Value::Object(obj).to_string(),
            ))
        };
        // An inline-hides page must suppress the host stylesheet even when
        // every selector was excepted and there is no JSON left to carry.
        if json.is_none() && !inline_hides {
            return None;
        }
        Some(CosmeticPayload { json, inline_hides })
    }
}

/// What one page needs inline, and whether its `<link rel=stylesheet>` must
/// be left out because a location/app-scoped exception changed the answer.
struct CosmeticPayload {
    json: Option<String>,
    inline_hides: bool,
}
