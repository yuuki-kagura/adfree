//! User-supplied scripts.
//!
//! The user writes JS and we keep the list; when serving `/adfree-user.js` (or
//! inlining), the scripts are stitched into one file. Keeping it separate means
//! one `<script src>` per response instead of full bodies inside the HTML.
//!
//! Tampermonkey metadata is honoured here, in the core, so every platform gets
//! the same `@match` / `@include` / `@exclude` / `@run-at` behaviour. The whole
//! list is still served as one file; a small guard at the start of each script
//! decides whether that script may run on the current page.

use regex::RegexBuilder;

/// Caps so a client never downloads too much. The byte cap has to fit real
/// userscripts (AdGuard Extra is ~560 KB), so it is generous; the combined
/// body is only rebuilt when the list changes, not per request.
pub const MAX_SCRIPTS: usize = 32;
pub const MAX_SCRIPT_BYTES: usize = 1024 * 1024;

/// Metadata limits: a broken header must not turn one download into thousands
/// of regexes. Real userscripts use a handful of patterns.
const MAX_META_PATTERNS: usize = 64;
const MAX_PATTERN_LEN: usize = 2048;
const MAX_REQUIRES: usize = 8;
const MAX_GRANTS: usize = 16;
const META_SCAN_LINES: usize = 256;

/// One user script.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserScript {
    /// Stable identifier: names the GM storage namespace and survives edits.
    pub id: String,
    pub name: String,
    pub body: String,
    pub enabled: bool,
}

/// Script list plus serving state.
#[derive(Clone, Debug)]
pub struct ScriptSet {
    scripts: Vec<ScriptEntry>,
    /// Master switch for script injection.
    pub enabled: bool,
    /// URL mà ta dùng trong `<script src>`.
    pub serve_path: String,
    /// The stitched body, rebuilt when the list changes: serving a page must
    /// never pay for re-stitching the scripts on every request.
    combined: std::sync::Arc<str>,
}

/// A script with its metadata already parsed and compiled.
#[derive(Clone, Debug)]
pub(crate) struct ScriptEntry {
    id: String,
    name: String,
    body: String,
    enabled: bool,
    meta: ScriptMeta,
}

#[derive(Clone, Debug)]
struct ScriptMeta {
    run_at: RunAt,
    noframes: bool,
    /// `@match` + `@include` patterns, combined as OR.
    allow: Vec<CompiledPattern>,
    exclude: Vec<CompiledPattern>,
    /// At least one `@match` / `@include` line was present. If every line is
    /// invalid, the script must not fall back to running everywhere.
    restrict: bool,
    version: String,
    /// `@grant` names, kept for `GM_info.script.grant` and a warning when the
    /// page runtime cannot provide one.
    grants: Vec<String>,
    /// Dependencies we cannot execute; kept only to warn in the page console.
    requires: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunAt {
    Start,
    End,
    Idle,
}

#[derive(Clone, Debug)]
struct CompiledPattern {
    /// Rust `regex` source. JS receives it through `new RegExp(...)`.
    source: String,
}

impl CompiledPattern {
    fn new(source: String) -> Option<Self> {
        // Validate once here. The page gets the source and runs the same
        // expression; the Rust copy is only needed by the unit tests.
        RegexBuilder::new(&source)
            .case_insensitive(true)
            .build()
            .ok()?;
        Some(Self { source })
    }

    #[cfg(test)]
    fn matches(&self, url: &str) -> bool {
        RegexBuilder::new(&self.source)
            .case_insensitive(true)
            .build()
            .map(|regex| regex.is_match(url))
            .unwrap_or(false)
    }

    fn test_js(&self) -> String {
        format!(
            "new RegExp({}, 'i').test(__adfree_href)",
            js_string(&self.source)
        )
    }
}

impl ScriptMeta {
    fn parse(body: &str) -> Self {
        let mut meta = Self {
            run_at: RunAt::Start,
            noframes: false,
            allow: Vec::new(),
            exclude: Vec::new(),
            restrict: false,
            version: String::new(),
            grants: Vec::new(),
            requires: Vec::new(),
        };

        let mut in_header = false;
        let mut saw_header = false;
        let mut run_at = None;

        for line in body.lines().take(META_SCAN_LINES) {
            let line = line.trim_start_matches('\u{feff}').trim_start();
            if !in_header {
                if line.starts_with("// ==UserScript==") {
                    in_header = true;
                    saw_header = true;
                }
                continue;
            }
            if line.starts_with("// ==/UserScript==") {
                break;
            }
            let Some(rest) = line.strip_prefix("//") else {
                continue;
            };
            let Some((key, value)) = split_key_value(rest.trim_start()) else {
                continue;
            };
            let value = value.trim();
            match key {
                "@match" => {
                    meta.restrict = true;
                    if let Some(pattern) = compile_match(value) {
                        push_pattern(&mut meta.allow, pattern);
                    }
                }
                "@include" => {
                    meta.restrict = true;
                    if let Some(pattern) = compile_glob(value) {
                        push_pattern(&mut meta.allow, pattern);
                    }
                }
                "@exclude" => {
                    if let Some(pattern) = compile_glob(value) {
                        push_pattern(&mut meta.exclude, pattern);
                    }
                }
                "@run-at" => {
                    run_at = Some(match value {
                        "document-start" => RunAt::Start,
                        "document-end" => RunAt::End,
                        "document-idle" => RunAt::Idle,
                        _ => continue,
                    })
                }
                "@noframes" => meta.noframes = true,
                "@version" if meta.version.is_empty() => meta.version = value.to_string(),
                "@grant" if !value.is_empty() => {
                    let name = value.trim();
                    if name != "none"
                        && meta.grants.len() < MAX_GRANTS
                        && !meta.grants.iter().any(|g| g == name)
                    {
                        meta.grants.push(name.to_string());
                    }
                }
                "@require" if !value.is_empty() && meta.requires.len() < MAX_REQUIRES => {
                    meta.requires.push(value.to_string());
                }
                _ => {}
            }
        }

        meta.run_at = run_at.unwrap_or(if saw_header {
            // Tampermonkey's default; headerless AdFree scripts keep the old
            // document-start behaviour so the built-in Extra still wins races.
            RunAt::Idle
        } else {
            RunAt::Start
        });
        meta
    }

    /// Test hook for the Rust side; the page runs the same sources in JS.
    #[cfg(test)]
    fn matches(&self, url: &str) -> bool {
        if self.exclude.iter().any(|p| p.matches(url)) {
            return false;
        }
        if self.allow.is_empty() {
            return !self.restrict;
        }
        self.allow.iter().any(|p| p.matches(url))
    }

    fn predicate_js(&self) -> String {
        let allow = if self.allow.is_empty() {
            if self.restrict {
                "false".to_string()
            } else {
                "true".to_string()
            }
        } else {
            self.allow
                .iter()
                .map(CompiledPattern::test_js)
                .collect::<Vec<_>>()
                .join(" || ")
        };

        if self.exclude.is_empty() {
            allow
        } else {
            let exclude = self
                .exclude
                .iter()
                .map(CompiledPattern::test_js)
                .collect::<Vec<_>>()
                .join(" || ");
            format!("!({exclude}) && ({allow})")
        }
    }
}

fn push_pattern(patterns: &mut Vec<CompiledPattern>, pattern: CompiledPattern) {
    if patterns.len() < MAX_META_PATTERNS {
        patterns.push(pattern);
    }
}

/// Split `@key value` without allocating. Metadata keys never contain spaces.
fn split_key_value(line: &str) -> Option<(&str, &str)> {
    if !line.starts_with('@') {
        return None;
    }
    let end = line
        .char_indices()
        .find(|(_, c)| c.is_whitespace())
        .map(|(i, _)| i)
        .unwrap_or(line.len());
    Some((&line[..end], line[end..].trim()))
}

/// Compile a Tampermonkey `@match` pattern:
/// `<scheme>://<host><path>`, with `*` allowed for scheme, a leading `*.` in
/// the host, and anywhere in the path.
fn compile_match(pattern: &str) -> Option<CompiledPattern> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
        return None;
    }
    let (scheme, rest) = pattern.split_once("://")?;
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "*" => "https?",
        "http" => "http",
        "https" => "https",
        _ => return None,
    };
    let (host, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/*"),
    };
    if host.is_empty() {
        return None;
    }

    let mut source = String::with_capacity(pattern.len() + 32);
    source.push('^');
    source.push_str(scheme);
    source.push_str("://");
    source.push_str(&host_regex(host)?);
    source.push_str(&path_regex(path));
    source.push('$');
    CompiledPattern::new(source)
}

/// Compile a Greasemonkey `@include` / `@exclude` glob against the full URL.
fn compile_glob(pattern: &str) -> Option<CompiledPattern> {
    if pattern.is_empty() || pattern.len() > MAX_PATTERN_LEN {
        return None;
    }
    let mut source = String::with_capacity(pattern.len() + 4);
    source.push('^');
    append_wildcard_regex(&mut source, pattern, ".*");
    source.push('$');
    CompiledPattern::new(source)
}

fn host_regex(host: &str) -> Option<String> {
    if host == "*" {
        return Some("[^/]+".to_string());
    }
    let (prefix, rest) = match host.strip_prefix("*.") {
        Some(rest) => ("(?:[^/]+\\.)*", rest),
        None => ("", host),
    };
    if rest.is_empty() || rest.contains('*') {
        // Match patterns only allow a wildcard for the whole host or as the
        // leading `*.` label. Anything else is invalid; treating it as a glob
        // would make `https://*example.com/*` match `evilexample.com`.
        return None;
    }
    let mut out = String::from(prefix);
    append_wildcard_regex(&mut out, rest, "[^/]*");
    Some(out)
}

fn path_regex(path: &str) -> String {
    let mut out = String::new();
    append_wildcard_regex(&mut out, path, ".*");
    // A `@match` path is matched without the query/fragment. Unless the user
    // ended it with `*`, allow either to follow the exact path.
    if !path.ends_with('*') {
        out.push_str("(?:[?#].*)?");
    }
    out
}

/// Append `pattern` to `out`, escaping literals and replacing `*` with
/// `wildcard`. Keeping one implementation means `@match` and `@include`
/// cannot disagree about dots, slashes or query characters.
fn append_wildcard_regex(out: &mut String, pattern: &str, wildcard: &str) {
    let mut literal = String::new();
    for ch in pattern.chars() {
        if ch == '*' {
            if !literal.is_empty() {
                out.push_str(&regex::escape(&literal));
                literal.clear();
            }
            out.push_str(wildcard);
        } else {
            literal.push(ch);
        }
    }
    if !literal.is_empty() {
        out.push_str(&regex::escape(&literal));
    }
}

/// A JS double-quoted string. Metadata is ASCII in practice, but escape
/// controls anyway so a weird pattern cannot break the served file.
fn js_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A JS array literal of strings, used by `GM_info.script.grant`.
fn js_string_array(values: &[String]) -> String {
    let mut out = String::from("[");
    for (i, value) in values.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&js_string(value));
    }
    out.push(']');
    out
}

/// `@require` URLs from the header, in order and deduplicated. The platform
/// downloads them once at install time; they never turn into page requests.
pub(crate) fn required_urls(body: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for url in ScriptMeta::parse(body).requires {
        if !out.contains(&url) {
            out.push(url);
        }
    }
    out
}

/// Put resolved `@require` bodies after the userscript header and remove the
/// `@require` lines, so the page runtime no longer warns about them. Failed
/// downloads leave a console warning in place of the missing body.
pub(crate) fn embed_requires(
    body: &str,
    loaded: &[(String, String)],
    failed: &[(String, String)],
) -> String {
    if loaded.is_empty() && failed.is_empty() {
        return body.to_string();
    }
    let mut block = String::from("// AdFree: @require dependencies\n");
    for (url, code) in loaded {
        block.push_str("/* @require ");
        block.push_str(&comment_name(url));
        block.push_str(" */\ntry{\n");
        block.push_str(code);
        if !code.ends_with('\n') {
            block.push('\n');
        }
        block.push_str("}catch(e){try{console.warn('AdFree: @require failed',");
        block.push_str(&js_string(url));
        block.push_str(",e);}catch(_){}}\n");
    }
    for (url, error) in failed {
        block.push_str("try{console.warn('AdFree: @require failed',");
        block.push_str(&js_string(url));
        block.push(',');
        block.push_str(&js_string(error));
        block.push_str(");}catch(e){}\n");
    }

    // If the header never closes, put the dependencies right after its start
    // line rather than before it: the metadata scanner still needs to see the
    // header within its window.
    let has_close = body.lines().take(META_SCAN_LINES).any(|line| {
        line.trim_start_matches('\u{feff}')
            .trim_start()
            .starts_with("// ==/UserScript==")
    });
    let mut out = String::with_capacity(body.len() + block.len());
    let mut in_header = false;
    let mut inserted = false;
    for line in body.split_inclusive('\n') {
        let trimmed = line.trim_start_matches('\u{feff}').trim_start();
        if trimmed.starts_with("// ==UserScript==") {
            in_header = true;
            out.push_str(line);
            if !has_close {
                if !line.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&block);
                inserted = true;
            }
            continue;
        }
        if in_header && trimmed.starts_with("// ==/UserScript==") {
            in_header = false;
            out.push_str(line);
            if !inserted {
                if !line.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(&block);
                inserted = true;
            }
            continue;
        }
        if in_header && trimmed.starts_with("// @require") {
            continue;
        }
        out.push_str(line);
    }
    if !inserted {
        out.insert_str(0, &block);
    }
    out
}

/// Page-context GM helpers that do not need extension privileges. Network
/// calls use the page's own `fetch`, so CORS and CSP still apply: this is a
/// compatibility shim, not a CORS bypass.
fn advanced_runtime_js() -> &'static str {
    r##"
var __adfree_fetch=window.fetch?window.fetch.bind(window):null;
var __adfree_supported_grants={unsafeWindow:1,GM_addStyle:1,GM_log:1,GM_info:1,GM_xmlhttpRequest:1,GM_download:1,GM_openInTab:1,GM_notification:1,GM_setClipboard:1,GM_addElement:1,GM_setValue:1,GM_getValue:1,GM_deleteValue:1,GM_listValues:1,GM_addValueChangeListener:1,GM_removeValueChangeListener:1,GM_registerMenuCommand:1,GM_unregisterMenuCommand:1};
var __adfree_gm_call=function(cb,value){if(typeof cb==='function'){try{cb(value);}catch(e){try{console.warn('AdFree: GM callback failed',e);}catch(_){}}}};
var __adfree_gm_headers=function(response){var out='';if(response.headers&&response.headers.forEach){response.headers.forEach(function(value,name){out+=name+': '+value+'\r\n';});}return out;};
var __adfree_gm_fail=function(details,kind,message){var result={readyState:4,status:0,statusText:'',responseText:'',response:null,responseHeaders:'',finalUrl:'',error:message};if(kind==='timeout'){__adfree_gm_call(details.ontimeout,result);}else if(kind==='abort'){__adfree_gm_call(details.onabort,result);}else{__adfree_gm_call(details.onerror,result);}};
var GM_xmlhttpRequest=function(details){
  details=details||{};
  var url=details.url;
  if(typeof url!=='string'||!url){__adfree_gm_fail(details,'error','missing url');return {abort:function(){}};}
  if(!__adfree_fetch){__adfree_gm_fail(details,'error','fetch is unavailable');return {abort:function(){}};}
  var method=(details.method||'GET').toUpperCase();
  var init={method:method,headers:details.headers||{},credentials:details.withCredentials?'include':'same-origin'};
  if(details.data!==undefined&&details.data!==null&&method!=='GET'&&method!=='HEAD'){init.body=details.data;}
  var controller=null;
  if(window.AbortController){controller=new window.AbortController();init.signal=controller.signal;}
  var timer=0;
  var timedOut=false;
  var aborted=false;
  var clearTimer=function(){if(timer){clearTimeout(timer);timer=0;}};
  var start={readyState:1,status:0,statusText:'',responseText:'',response:null,responseHeaders:'',finalUrl:url};
  __adfree_gm_call(details.onloadstart,start);
  __adfree_gm_call(details.onreadystatechange,start);
  if(details.timeout>0){timer=setTimeout(function(){timedOut=true;if(controller){controller.abort();}},details.timeout);}
  __adfree_fetch(url,init).then(function(response){
    var type=details.responseType||'';
    var reader=type==='arraybuffer'?response.arrayBuffer():type==='blob'?response.blob():response.text();
    return reader.then(function(payload){
      var text=typeof payload==='string'?payload:'';
      var value=payload;
      if(type==='json'){try{value=JSON.parse(text);}catch(e){value=null;}}
      var result={readyState:4,status:response.status,statusText:response.statusText,responseText:text,response:value,responseHeaders:__adfree_gm_headers(response),finalUrl:response.url||url};
      __adfree_gm_call(details.onreadystatechange,result);
      __adfree_gm_call(details.onprogress,{readyState:4,status:response.status,statusText:response.statusText,responseText:text,response:value,responseHeaders:result.responseHeaders,finalUrl:result.finalUrl,loaded:text.length,total:text.length,lengthComputable:true});
      __adfree_gm_call(details.onload,result);
    });
  }).then(clearTimer,function(error){
    clearTimer();
    if(timedOut){__adfree_gm_fail(details,'timeout','timeout');}
    else if(aborted){__adfree_gm_fail(details,'abort','aborted');}
    else{__adfree_gm_fail(details,'error',String(error&&error.message?error.message:error));}
  });
  return {abort:function(){aborted=true;if(controller){controller.abort();}}};
};
var GM_download=function(details){
  if(typeof details==='string'){details={url:details};}
  details=details||{};
  if(typeof details.url!=='string'||!details.url){__adfree_gm_call(details.onerror,{error:'missing url'});return;}
  if(!__adfree_fetch){__adfree_gm_call(details.onerror,{error:'fetch is unavailable'});return;}
  __adfree_fetch(details.url,{credentials:'same-origin'}).then(function(response){
    if(!response.ok){throw new Error('HTTP '+response.status);}
    return response.blob();
  }).then(function(blob){
    var a=document.createElement('a');
    var href=URL.createObjectURL(blob);
    a.href=href;
    a.download=details.name||'';
    a.style.display='none';
    (document.body||document.documentElement).appendChild(a);
    a.click();
    setTimeout(function(){URL.revokeObjectURL(href);if(a.parentNode){a.parentNode.removeChild(a);}},1000);
    __adfree_gm_call(details.onload,{status:200,finalUrl:details.url});
  },function(error){__adfree_gm_call(details.onerror,{error:String(error&&error.message?error.message:error)});});
};
var GM_openInTab=function(url){try{var w=window.open(url,'_blank','noopener');if(w){try{w.opener=null;}catch(e){}}return w;}catch(e){return null;}};
var GM_notification=function(text,title,image,onclick){
  var options={};
  if(text&&typeof text==='object'){options=text;}else{options={text:text,title:title,image:image,onclick:onclick};}
  var done=function(){__adfree_gm_call(options.ondone,{});};
  var fail=function(message){__adfree_gm_call(options.onerror,{error:message});done();};
  if(typeof Notification!=='function'){console.warn('AdFree: notifications are not available');done();return null;}
  var show=function(){
    try{
      var n=new Notification(options.title||'AdFree',{body:String(options.text||''),icon:options.image||undefined});
      n.onclick=function(){__adfree_gm_call(options.onclick,n);};
      n.onclose=done;
      setTimeout(done,0);
      return n;
    }catch(e){fail(String(e&&e.message?e.message:e));return null;}
  };
  if(Notification.permission==='granted'){return show();}
  if(Notification.permission==='denied'){fail('notifications are denied');return null;}
  try{Notification.requestPermission().then(function(permission){if(permission==='granted'){show();}else{fail('notifications are denied');}});}catch(e){fail(String(e&&e.message?e.message:e));}
  return null;
};
var GM_setClipboard=function(text){
  text=String(text==null?'':text);
  try{
    if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(text).catch(function(e){console.warn('AdFree: clipboard write failed',e);});return;}
    var area=document.createElement('textarea');
    area.value=text;
    area.style.position='fixed';
    area.style.opacity='0';
    (document.body||document.documentElement).appendChild(area);
    area.select();
    document.execCommand('copy');
    if(area.parentNode){area.parentNode.removeChild(area);}
  }catch(e){console.warn('AdFree: clipboard write failed',e);}
};
var GM_addElement=function(parent,tag,attributes){
  if(typeof parent==='string'){attributes=tag;tag=parent;parent=document.head||document.documentElement;}
  if(!parent||!tag){return null;}
  var el=document.createElement(tag);
  if(attributes){Object.keys(attributes).forEach(function(key){if(key==='textContent'){el.textContent=attributes[key];}else if(key==='innerHTML'){el.innerHTML=attributes[key];}else{el.setAttribute(key,attributes[key]);}});}
  parent.appendChild(el);
  return el;
};
/*
 * Menu commands. There is no extension toolbar, so the host is a small
 * floating panel in a closed shadow root: page CSS cannot move it, and the
 * commands stay reachable without a native bridge.
 */
var __adfree_gm_menu_items=[];
var __adfree_gm_menu_host=null;
var __adfree_gm_menu_panel=null;
var __adfree_gm_menu_next=0;
var __adfree_gm_menu_draw=function(){
  var host=__adfree_gm_menu_host;
  if(!host){return;}
  var panel=__adfree_gm_menu_panel;
  while(panel.firstChild){panel.removeChild(panel.firstChild);}
  var title=document.createElement('div');
  title.textContent='AdFree scripts';
  title.style.cssText='font:600 12px sans-serif;color:#e6e8ef;padding:6px 10px;border-bottom:1px solid #333a4d;';
  panel.appendChild(title);
  __adfree_gm_menu_items.forEach(function(item){
    var button=document.createElement('button');
    button.type='button';
    button.textContent=item.label;
    button.style.cssText='display:block;width:100%;text-align:left;background:none;border:0;color:#c8cde0;font:12px sans-serif;padding:7px 10px;cursor:pointer;';
    if(item.script){button.title=item.script;}
    button.addEventListener('click',function(){
      panel.style.display='none';
      try{item.run();}catch(e){try{console.warn('AdFree: menu command failed',e);}catch(_){}}
    });
    panel.appendChild(button);
  });
  if(!__adfree_gm_menu_items.length){
    var empty=document.createElement('div');
    empty.textContent='No commands';
    empty.style.cssText='font:12px sans-serif;color:#8b91a8;padding:8px 10px;';
    panel.appendChild(empty);
  }
};
var __adfree_gm_menu_ensure=function(){
  if(__adfree_gm_menu_host){return;}
  if(!document.documentElement){return;}
  var host=document.createElement('div');
  host.style.cssText='position:fixed;right:12px;bottom:12px;z-index:2147483647;font:12px sans-serif;';
  var root=host.attachShadow?host.attachShadow({mode:'closed'}):host;
  var toggle=document.createElement('button');
  toggle.type='button';
  toggle.textContent='\u2699';
  toggle.title='AdFree menu';
  toggle.style.cssText='width:34px;height:34px;border-radius:50%;border:1px solid #5b4ac9;background:#221f3b;color:#fff;font-size:16px;line-height:1;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.4);';
  var panel=document.createElement('div');
  panel.style.cssText='display:none;position:absolute;right:0;bottom:42px;min-width:180px;max-width:280px;background:#161b26;border:1px solid #333a4d;border-radius:8px;overflow:hidden;box-shadow:0 6px 24px rgba(0,0,0,.5);';
  toggle.addEventListener('click',function(){
    panel.style.display=panel.style.display==='none'?'block':'none';
  });
  root.appendChild(toggle);
  root.appendChild(panel);
  document.documentElement.appendChild(host);
  __adfree_gm_menu_host=host;
  __adfree_gm_menu_panel=panel;
};
var __adfree_gm_menu_register=function(script,label,run,accessKey){
  if(typeof label!=='string'||!label||typeof run!=='function'){return '';}
  var id='gm-menu-'+(++__adfree_gm_menu_next);
  __adfree_gm_menu_items.push({id:id,script:script,label:label,run:run,key:accessKey});
  __adfree_gm_menu_ensure();
  __adfree_gm_menu_draw();
  return id;
};
var __adfree_gm_menu_unregister=function(id){
  __adfree_gm_menu_items=__adfree_gm_menu_items.filter(function(item){return item.id!==id;});
  __adfree_gm_menu_draw();
};
"##
}

impl ScriptEntry {
    fn new(script: UserScript) -> Self {
        let meta = ScriptMeta::parse(&script.body);
        Self {
            id: script.id,
            name: script.name,
            body: script.body,
            enabled: script.enabled,
            meta,
        }
    }

    /// One self-contained IIFE: match guard, runtime shims, try/catch, and the
    /// user's body. The guard means a page only pays for the bodies selected
    /// for it at execution time, even though the file is shared.
    fn wrapped_js(&self) -> String {
        let mut out = String::with_capacity(self.body.len() + 512);
        out.push_str("/* ");
        out.push_str(&comment_name(&self.name));
        out.push_str(" */\n");
        out.push_str("(function(){\n");
        out.push_str("var __adfree_href=location.href;\n");
        out.push_str("if(!(");
        out.push_str(&self.meta.predicate_js());
        out.push_str("))return;\n");
        if self.meta.noframes {
            out.push_str("if(window.top!==window)return;\n");
        }
        out.push_str("var __adfree_run=function(){\n");
        // Page-context shims. The advanced network helpers live once in the
        // outer IIFE (build_combined); storage and the menu are per script.
        out.push_str("var unsafeWindow=window;\n");
        out.push_str("var GM_info={scriptHandler:'AdFree',version:'1.0',script:{name:");
        out.push_str(&js_string(&self.name));
        out.push_str(",version:");
        out.push_str(&js_string(&self.meta.version));
        out.push_str(",grant:");
        out.push_str(&js_string_array(&self.meta.grants));
        out.push_str("}};\n");
        // Greasemonkey storage. The runtime is the page's main world, so the
        // only synchronous store available is this origin's localStorage;
        // values are namespaced per script. They do not travel across origins
        // the way a browser extension's storage would.
        let ns = if self.id.is_empty() {
            &self.name
        } else {
            &self.id
        };
        out.push_str("var __adfree_gm_prefix='adfree.gm.'+");
        out.push_str(&js_string(ns));
        out.push_str("+'.';\n");
        out.push_str(
            "var __adfree_gm_key=function(key){return __adfree_gm_prefix+String(key);};\n\
var __adfree_gm_listeners=Object.create(null);\n\
var __adfree_gm_value_next=0;\n\
var __adfree_gm_notify=function(key,oldValue,newValue,remote){var list=__adfree_gm_listeners[String(key)];if(!list){return;}list.slice().forEach(function(fn){try{fn(String(key),oldValue,newValue,!!remote);}catch(e){try{console.warn('AdFree: GM value listener failed',e);}catch(_){}}});};\n\
var GM_getValue=function(key,fallback){try{var raw=localStorage.getItem(__adfree_gm_key(key));if(raw===null){return fallback;}return JSON.parse(raw);}catch(e){return fallback;}};\n\
var GM_setValue=function(key,value){var name=String(key);var oldValue=GM_getValue(name);var raw;try{raw=JSON.stringify(value);}catch(e){console.warn('AdFree: GM_setValue cannot serialize',e);return;}try{localStorage.setItem(__adfree_gm_key(name),raw);}catch(e){console.warn('AdFree: GM_setValue failed',e);return;}__adfree_gm_notify(name,oldValue,value,false);};\n\
var GM_deleteValue=function(key){var name=String(key);var oldValue=GM_getValue(name);try{localStorage.removeItem(__adfree_gm_key(name));}catch(e){console.warn('AdFree: GM_deleteValue failed',e);return;}__adfree_gm_notify(name,oldValue,undefined,false);};\n\
var GM_listValues=function(){var out=[];try{for(var i=0;i<localStorage.length;i++){var key=localStorage.key(i);if(key&&key.indexOf(__adfree_gm_prefix)===0){out.push(key.slice(__adfree_gm_prefix.length));}}}catch(e){}return out;};\n\
var GM_addValueChangeListener=function(key,fn){if(typeof fn!=='function'){return '';}var name=String(key);var id='gm-value-'+(++__adfree_gm_value_next);(__adfree_gm_listeners[name]||(__adfree_gm_listeners[name]=[])).push(fn);fn.__adfree_gm_id=id;return id;};\n\
var GM_removeValueChangeListener=function(id){Object.keys(__adfree_gm_listeners).forEach(function(key){__adfree_gm_listeners[key]=__adfree_gm_listeners[key].filter(function(fn){return fn.__adfree_gm_id!==id;});});};\n",
        );
        out.push_str("var GM_registerMenuCommand=function(label,run,accessKey){return __adfree_gm_menu_register(");
        out.push_str(&js_string(&self.name));
        out.push_str(",label,run,accessKey);};\n");
        out.push_str(
            "var GM_unregisterMenuCommand=function(id){__adfree_gm_menu_unregister(id);};\n",
        );
        if !self.meta.grants.is_empty() {
            out.push_str("var __adfree_grants=");
            out.push_str(&js_string_array(&self.meta.grants));
            out.push_str(";var __adfree_missing=__adfree_grants.filter(function(g){return !__adfree_supported_grants[g];});");
            out.push_str("if(__adfree_missing.length){try{console.warn('AdFree: unsupported @grant: '+__adfree_missing.join(', '));}catch(e){}}\n");
        }
        out.push_str(
            "var GM_addStyle=function(css){var s=document.createElement('style');s.textContent=css;(document.head||document.documentElement).appendChild(s);return s;};\n",
        );
        out.push_str(
            "var GM_log=function(){try{console.log.apply(console,arguments);}catch(e){}};\n",
        );
        if !self.meta.requires.is_empty() {
            out.push_str(
                "console.warn('AdFree: @require is not supported by this userscript host');\n",
            );
        }
        out.push_str("try{\n");
        out.push_str(&self.body);
        out.push_str("\n}catch(e){console.warn('AdFree script failed: '+");
        out.push_str(&js_string(&self.name));
        out.push_str(",e);}\n");
        out.push_str("};\n");

        match self.meta.run_at {
            RunAt::Start => out.push_str("__adfree_run();\n"),
            RunAt::End => out.push_str(
                "if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',__adfree_run,{once:true});}else{__adfree_run();}\n",
            ),
            RunAt::Idle => out.push_str(
                "var __adfree_idle=function(){if(window.requestIdleCallback){window.requestIdleCallback(__adfree_run);}else{window.setTimeout(__adfree_run,1);}};if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',__adfree_idle,{once:true});}else{__adfree_idle();}\n",
            ),
        }
        out.push_str("})();\n");
        out
    }
}

fn comment_name(name: &str) -> String {
    let mut out = name.replace("*/", "* /").replace(['\n', '\r'], " ");
    if out.len() > 80 {
        let mut end = 80;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push('…');
    }
    out
}

impl Default for ScriptSet {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptSet {
    pub fn new() -> Self {
        ScriptSet {
            scripts: Vec::new(),
            enabled: false,
            serve_path: "/adfree-user.js".to_string(),
            combined: std::sync::Arc::from(""),
        }
    }

    /// Replace the whole list, dropping over-long or empty entries.
    pub fn replace_all(&mut self, scripts: Vec<UserScript>) -> usize {
        self.scripts = scripts
            .into_iter()
            .filter(|s| !s.name.is_empty() && !s.body.is_empty())
            .filter(|s| s.body.len() <= MAX_SCRIPT_BYTES)
            .take(MAX_SCRIPTS)
            .map(ScriptEntry::new)
            .collect();
        self.recompute();
        self.scripts.len()
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
        self.recompute();
    }

    /// Rebuilds the served body; called after any state change.
    ///
    /// The master switch alone is not enough: with every script disabled the
    /// stitched file would hold only the runtime scaffolding, which is a tag
    /// (and a fetch) every page pays for and no script needs.
    fn recompute(&mut self) {
        let any_enabled = self.scripts.iter().any(|script| script.enabled);
        self.combined = if self.enabled && any_enabled {
            std::sync::Arc::from(self.build_combined().as_str())
        } else {
            std::sync::Arc::from("")
        };
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled && !self.scripts.is_empty()
    }

    pub(crate) fn scripts(&self) -> &[ScriptEntry] {
        &self.scripts
    }

    /// Combined JS body (enabled scripts only).
    pub fn combined_js(&self) -> String {
        self.combined.to_string()
    }

    /// Cheap handle for the serving path: cloning an `Arc` beats copying a
    /// megabyte of JS for every intercepted connection.
    pub fn combined_arc(&self) -> std::sync::Arc<str> {
        std::sync::Arc::clone(&self.combined)
    }

    /// Stitches the enabled scripts into one body wrapped per script.
    fn build_combined(&self) -> String {
        let mut out = String::with_capacity(256);
        out.push_str("/* AdFree user scripts */\n");
        out.push_str("(function(){'use strict';\n");
        out.push_str(advanced_runtime_js());
        for script in self.scripts.iter().filter(|s| s.enabled) {
            out.push_str(&script.wrapped_js());
        }
        out.push_str("})();\n");
        out
    }

    /// The path we answer when a client requests it, or `""` when there is
    /// nothing to serve. An empty path is what keeps the HTML rewrite from
    /// emitting a `<script src>` for a bundle that does not exist (master
    /// switch off, or every script disabled): that tag could only 404.
    pub fn serve_path(&self) -> &str {
        if self.combined.is_empty() {
            ""
        } else {
            &self.serve_path
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn script(name: &str, body: &str) -> UserScript {
        UserScript {
            id: name.to_string(),
            name: name.to_string(),
            body: body.to_string(),
            enabled: true,
        }
    }

    fn meta(body: &str) -> ScriptMeta {
        ScriptMeta::parse(body)
    }

    #[test]
    fn disabled_set_serves_nothing() {
        let mut set = ScriptSet::new();
        set.replace_all(vec![script("a", "console.log(1)")]);
        assert!(set.combined_js().is_empty());
        set.set_enabled(true);
        assert!(set.is_enabled());
        assert!(set.combined_js().contains("console.log(1)"));
    }

    #[test]
    fn replaces_the_whole_list() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![
            script("one", "let a = 1;"),
            script("two", "let b = 2;"),
        ]);
        assert_eq!(set.scripts().len(), 2);
        set.replace_all(vec![script("only", "let c = 3;")]);
        assert_eq!(set.scripts().len(), 1);
        let js = set.combined_js();
        assert!(js.contains("let c = 3;"));
        assert!(!js.contains("let a = 1;"));
    }

    /// The YouTube module ships with the core, so its `@match` lines are the
    /// only thing deciding whether it runs: a host that ignored them would put
    /// a YouTube module on every page, and one that misread them would leave
    /// YouTube unfixed while the row in the app said "on".
    #[test]
    fn the_youtube_module_runs_on_youtube_only() {
        let body = crate::filter::YOUTUBE_JS;
        let parsed = meta(body);
        assert!(parsed.restrict, "the module is not allowed to run everywhere");
        assert!(parsed.matches("https://www.youtube.com/watch?v=1"));
        assert!(parsed.matches("https://m.youtube.com/"));
        assert!(!parsed.matches("https://example.com/"));
        assert!(!parsed.matches("https://notyoutube.com/"));
        assert_eq!(parsed.run_at, RunAt::Start);
    }

    #[test]
    fn filters_empty_and_huge_scripts() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        let huge = "x".repeat(MAX_SCRIPT_BYTES + 1);
        set.replace_all(vec![
            UserScript {
                id: String::new(),
                name: String::new(),
                body: "a".into(),
                enabled: true,
            },
            UserScript {
                id: "empty".into(),
                name: "empty".into(),
                body: String::new(),
                enabled: true,
            },
            UserScript {
                id: "big".into(),
                name: "big".into(),
                body: huge,
                enabled: true,
            },
            script("ok", "let ok = true;"),
        ]);
        assert_eq!(set.scripts().len(), 1);
        assert_eq!(set.scripts()[0].name, "ok");
    }

    #[test]
    fn caps_the_number_of_scripts() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        let many: Vec<UserScript> = (0..40)
            .map(|i| script(&format!("s{i}"), "console.log(1)"))
            .collect();
        set.replace_all(many);
        assert_eq!(set.scripts().len(), MAX_SCRIPTS);
    }

    #[test]
    fn only_enabled_scripts_are_combined() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![
            script("on", "let on = 1;"),
            UserScript {
                id: "off".into(),
                name: "off".into(),
                body: "let off = 1;".into(),
                enabled: false,
            },
        ]);
        let js = set.combined_js();
        assert!(js.contains("let on = 1;"));
        assert!(!js.contains("let off = 1;"));
    }

    #[test]
    fn combined_js_wraps_each_script_in_try_catch() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script("broken", "this is not javascript ((")]);
        let js = set.combined_js();
        assert!(js.contains("try{"), "every script must be isolated");
        assert!(js.contains("}catch(e)"));
        assert!(js.contains("'use strict'"));
    }

    #[test]
    fn serve_path_is_empty_until_a_body_exists() {
        let mut set = ScriptSet::new();
        assert_eq!(set.serve_path(), "", "no scripts means no tag");
        set.replace_all(vec![script("a", "let a = 1;")]);
        assert_eq!(set.serve_path(), "", "master switch still off");
        set.set_enabled(true);
        assert_eq!(set.serve_path(), "/adfree-user.js");
        set.set_enabled(false);
        assert_eq!(set.serve_path(), "", "master switch off serves nothing");
    }

    #[test]
    fn all_scripts_disabled_serves_no_body() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![UserScript {
            id: "off".into(),
            name: "off".into(),
            body: "let off = 1;".into(),
            enabled: false,
        }]);
        assert!(set.combined_arc().is_empty());
        assert_eq!(set.serve_path(), "");
    }

    #[test]
    fn combined_arc_follows_state_changes() {
        let mut set = ScriptSet::new();
        assert!(set.combined_arc().is_empty());
        set.replace_all(vec![script("a", "let a = 1;")]);
        assert!(set.combined_arc().is_empty(), "master switch still off");
        set.set_enabled(true);
        assert!(set.combined_arc().contains("let a = 1;"));
        set.set_enabled(false);
        assert!(set.combined_arc().is_empty());
    }

    #[test]
    fn match_and_exclude_choose_pages() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://*.example.com/*\n\
             // @exclude https://ads.example.com/*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://example.com/"));
        assert!(meta.matches("https://www.example.com/page"));
        assert!(!meta.matches("http://www.example.com/page"));
        assert!(!meta.matches("https://ads.example.com/banner"));
        assert!(!meta.matches("https://example.org/"));
    }

    #[test]
    fn match_all_covers_http_and_https_pages() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match *://*/*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://example.com/"));
        assert!(meta.matches("http://example.com/path?q=1"));
        assert!(!meta.matches("ftp://example.com/"));
    }

    #[test]
    fn a_path_match_accepts_a_query_unless_it_ends_with_star() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://example.com/watch\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://example.com/watch"));
        assert!(meta.matches("https://example.com/watch?v=1"));
        assert!(!meta.matches("https://example.com/watch/extra"));
    }

    #[test]
    fn includes_are_or_with_matches() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://a.example/*\n\
             // @include https://b.example/*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://a.example/page"));
        assert!(meta.matches("https://b.example/page"));
        assert!(!meta.matches("https://c.example/page"));
    }

    #[test]
    fn include_globs_can_name_a_fragment_of_the_url() {
        let meta = meta(
            "// ==UserScript==\n\
             // @include *wikipedia.org*\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://vi.wikipedia.org/wiki/Trang_ch%E1%BB%A7"));
        assert!(!meta.matches("https://example.org/"));
    }

    #[test]
    fn a_header_without_patterns_keeps_legacy_run_everywhere() {
        let meta = meta(
            "// ==UserScript==\n\
             // @name only-a-name\n\
             // ==/UserScript==\n",
        );
        assert!(meta.matches("https://anything.example/"));
        assert_eq!(meta.run_at, RunAt::Idle);
    }

    #[test]
    fn no_header_keeps_document_start_and_runs_everywhere() {
        let meta = meta("console.log('plain')");
        assert!(meta.matches("https://anything.example/"));
        assert_eq!(meta.run_at, RunAt::Start);
    }

    #[test]
    fn run_at_and_noframes_are_parsed() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://example.com/*\n\
             // @run-at document-end\n\
             // @noframes\n\
             // ==/UserScript==\n",
        );
        assert_eq!(meta.run_at, RunAt::End);
        assert!(meta.noframes);
    }

    #[test]
    fn an_invalid_match_does_not_open_the_script_everywhere() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match not-a-match-pattern\n\
             // ==/UserScript==\n",
        );
        assert!(!meta.matches("https://example.com/"));
    }

    #[test]
    fn a_wildcard_inside_the_host_is_not_a_suffix_glob() {
        let meta = meta(
            "// ==UserScript==\n\
             // @match https://*example.com/*\n\
             // ==/UserScript==\n",
        );
        assert!(!meta.matches("https://evilexample.com/"));
        assert!(!meta.matches("https://example.com/"));
    }

    #[test]
    fn match_guard_and_run_at_reach_the_served_body() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script(
            "scoped",
            "// ==UserScript==\n\
             // @match https://example.com/*\n\
             // @run-at document-end\n\
             // ==/UserScript==\n\
             window.__scoped = true;",
        )]);
        let js = set.combined_js();
        assert!(
            js.contains("new RegExp("),
            "the match source must reach the page"
        );
        assert!(js.contains("document.readyState==='loading'"));
        assert!(js.contains("DOMContentLoaded"));
        assert!(js.contains("window.__scoped = true;"));
    }

    #[test]
    fn document_idle_uses_request_idle_callback() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script(
            "idle",
            "// ==UserScript==\n\
             // @match *://*/*\n\
             // ==/UserScript==\n\
             window.__idle = true;",
        )]);
        let js = set.combined_js();
        assert!(js.contains("requestIdleCallback"));
    }

    #[test]
    fn grants_are_deduplicated_and_reach_gm_info() {
        let body = "// ==UserScript==\n\
                    // @grant GM_xmlhttpRequest\n\
                    // @grant none\n\
                    // @grant GM_setValue\n\
                    // @grant GM_xmlhttpRequest\n\
                    // ==/UserScript==\n\
                    window.__grant = true;";
        let meta = meta(body);
        assert_eq!(meta.grants, vec!["GM_xmlhttpRequest", "GM_setValue"]);
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script("granted", body)]);
        let js = set.combined_js();
        assert!(js.contains("grant:[\"GM_xmlhttpRequest\",\"GM_setValue\"]"));
        assert!(js.contains("unsupported @grant"));
    }

    #[test]
    fn require_urls_are_deduplicated_in_header_order() {
        let body = "// ==UserScript==\n\
                    // @require https://cdn.example/a.js\n\
                    // @require https://cdn.example/b.js\n\
                    // @require https://cdn.example/a.js\n\
                    // ==/UserScript==\n\
                    window.__requires = true;";
        assert_eq!(
            required_urls(body),
            vec!["https://cdn.example/a.js", "https://cdn.example/b.js"]
        );
    }

    #[test]
    fn embed_requires_runs_dependencies_before_the_body_and_drops_header_lines() {
        let body = "// ==UserScript==\n\
                    // @name dependency\n\
                    // @require https://cdn.example/lib.js\n\
                    // ==/UserScript==\n\
                    window.__body = true;";
        let out = embed_requires(
            body,
            &[(
                "https://cdn.example/lib.js".to_string(),
                "window.__dependency = true;".to_string(),
            )],
            &[],
        );
        assert!(!out.contains("// @require https://cdn.example/lib.js"));
        assert!(out.contains("window.__dependency = true;"));
        let dep = out.find("window.__dependency = true;").unwrap();
        let user = out.find("window.__body = true;").unwrap();
        assert!(dep < user, "dependencies must run before the script body");
        assert!(out.contains("// ==UserScript=="));
    }

    #[test]
    fn a_failed_require_leaves_a_console_warning_not_a_header_line() {
        let body = "// ==UserScript==\n\
                    // @require https://cdn.example/missing.js\n\
                    // ==/UserScript==\n\
                    window.__body = true;";
        let out = embed_requires(
            body,
            &[],
            &[(
                "https://cdn.example/missing.js".to_string(),
                "HTTP 404".to_string(),
            )],
        );
        assert!(!out.contains("// @require https://cdn.example/missing.js"));
        assert!(out.contains("console.warn('AdFree: @require failed'"));
        assert!(out.contains("HTTP 404"));
    }

    #[test]
    fn advanced_gm_helpers_are_page_safe_and_storage_is_namespaced() {
        let mut set = ScriptSet::new();
        set.set_enabled(true);
        set.replace_all(vec![script(
            "advanced",
            "// ==UserScript==\n\
             // @grant GM_xmlhttpRequest\n\
             // @grant GM_setValue\n\
             // ==/UserScript==\n\
             GM_xmlhttpRequest({url: location.href});",
        )]);
        let js = set.combined_js();
        assert!(js.contains("var GM_xmlhttpRequest="));
        assert!(js.contains("var GM_download="));
        assert!(js.contains("var GM_openInTab="));
        assert!(js.contains("var GM_notification="));
        assert!(js.contains("var GM_setClipboard="));
        assert!(js.contains("var GM_addElement="));
        assert!(js.contains("var GM_setValue="));
        assert!(js.contains("var GM_getValue="));
        assert!(js.contains("var GM_deleteValue="));
        assert!(js.contains("var GM_listValues="));
        assert!(js.contains("var GM_registerMenuCommand="));
        assert!(js.contains("adfree.gm.'+"));
        assert!(js.contains("credentials:details.withCredentials?'include':'same-origin'"));
    }
}
