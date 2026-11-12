# [1.5.0](https://github.com/yuuki-kagura/adfree/compare/v1.4.0...v1.5.0) (2026-11-12)


### Bug Fixes

* **core:** clear the lints a newer toolchain raises, both targets ([bd81e78](https://github.com/yuuki-kagura/adfree/commit/bd81e78834f0467e7b900d7cee6ef468d1f7ff80))
* **core:** enable the IP helper feature the process lookup needs ([7561bc3](https://github.com/yuuki-kagura/adfree/commit/7561bc35937f76b48b4593cb14a8ee5edabd9b38))
* **desktop:** an MSI version, which WiX has strict ideas about ([9a8cda9](https://github.com/yuuki-kagura/adfree/commit/9a8cda9cb4b3a1ab7cc9011c0259be1752a9a0f1))


### Features

* **core:** decide what the Windows redirector does, and test it on Linux ([8935655](https://github.com/yuuki-kagura/adfree/commit/89356554d6cb2164fca23df508e375fd8e1eb092))
* **core:** let the app start the redirect, on every platform ([40c70c2](https://github.com/yuuki-kagura/adfree/commit/40c70c22ba6fa78af74a7ea9a46a4407919e6257))
* **core:** the filtering core builds for Windows ([f993156](https://github.com/yuuki-kagura/adfree/commit/f993156633b5dfe470bb207640e164cc7afa6cf6))
* **core:** the wait set is epoll on Windows too, over IOCP ([9e796de](https://github.com/yuuki-kagura/adfree/commit/9e796de66fb220b378d63e7731929b8b1dbea7ed))
* **core:** the Windows redirect, wired to WinDivert ([5303b9b](https://github.com/yuuki-kagura/adfree/commit/5303b9bda2618b6397eb9a53bf92dc6c18a6e4ec))
* **core:** trust the local CA on Windows through the machine's store ([a615155](https://github.com/yuuki-kagura/adfree/commit/a615155c1ed4ff52eb43629563a3ad2591541150))
* **desktop:** answer the privilege questions for a Windows machine ([06044d5](https://github.com/yuuki-kagura/adfree/commit/06044d51a9b513b2c4ecd55df9bc2361f04dc074))
* **desktop:** find the core and the driver on Windows ([2b20b81](https://github.com/yuuki-kagura/adfree/commit/2b20b811a269f572e86c7a9ddbcc6c05d9c9f09a))
* **desktop:** register the extension's host on Windows, where Chrome reads a registry ([9978697](https://github.com/yuuki-kagura/adfree/commit/9978697f087a0073c5146025aa04ccc587bb62b9))
* the tray's state, the log's process names, and the arm builds ([ff8b0f3](https://github.com/yuuki-kagura/adfree/commit/ff8b0f32d86cc15ebf8f42438338db9d58d7e998))

# [1.4.0](https://github.com/yuuki-kagura/adfree/compare/v1.3.3...v1.4.0) (2026-11-11)


### Bug Fixes

* **home:** the counters outlive the process, and the trackers are counted ([c22213e](https://github.com/yuuki-kagura/adfree/commit/c22213e2ffb94d126458fe4acc086c279423f3b7))


### Features

* **log:** the tab's shape follows the platform, the popup keeps its own ([f06b348](https://github.com/yuuki-kagura/adfree/commit/f06b348af9ab19b64b88da4ae364fe7c3e5c831b))

## [1.3.3](https://github.com/yuuki-kagura/adfree/compare/v1.3.2...v1.3.3) (2026-11-11)


### Bug Fixes

* **proxy:** a stop must not take back the slots threads still hold ([bf5f63e](https://github.com/yuuki-kagura/adfree/commit/bf5f63e3b29dc1c64f0a7d8fec9c6d15bed0e03c))

## [1.3.2](https://github.com/yuuki-kagura/adfree/compare/v1.3.1...v1.3.2) (2026-11-11)


### Bug Fixes

* **proxy:** a pause finishes what it interrupted ([510a64f](https://github.com/yuuki-kagura/adfree/commit/510a64f5d33768112c9bdbe6b7d71b09cd7251bb))

## [1.3.1](https://github.com/yuuki-kagura/adfree/compare/v1.3.0...v1.3.1) (2026-11-11)


### Bug Fixes

* **packaging:** build the Arch package with the hardening flags off ([8315c60](https://github.com/yuuki-kagura/adfree/commit/8315c60afe8e0c6a9d51938bd407fe5a9f84fe0c))
* **packaging:** stop shipping a core that cannot be opened ([59769e6](https://github.com/yuuki-kagura/adfree/commit/59769e61cb650b98d16d27d5a5fb714a63a45f71))

# [1.3.0](https://github.com/yuuki-kagura/adfree/compare/v1.2.0...v1.3.0) (2026-11-11)


### Features

* **desktop:** hand a Linux user something to install ([1b85fe2](https://github.com/yuuki-kagura/adfree/commit/1b85fe209718a73030d88e89b438bbbe6ae498cd))

# [1.2.0](https://github.com/yuuki-kagura/adfree/compare/v1.1.1...v1.2.0) (2026-11-11)


### Bug Fixes

* **apps:** attribute connections on Android 10+ ([27314bc](https://github.com/yuuki-kagura/adfree/commit/27314bc918d2f01f2beb91ab0e1dd088bb2f8b6d))
* **apps:** show real per-app blocking stats and log icons ([aad5b95](https://github.com/yuuki-kagura/adfree/commit/aad5b95b8c90af9d77107c0ce15a56e424fd2989))
* **deps:** fetch the patched adblock fork from an account that exists ([87a91df](https://github.com/yuuki-kagura/adfree/commit/87a91df8ef55bd96db84e156a88e45e0d78e06b2))
* **desktop:** keep the browser extension's panel out of its loading state ([7b99b7f](https://github.com/yuuki-kagura/adfree/commit/7b99b7ff442dcaad835a5b43cda48ae3f53cea7d))
* **desktop:** keep the extension popup's state honest and never let it hang ([2843b54](https://github.com/yuuki-kagura/adfree/commit/2843b54dcd28e47c5043f6f517710907213a368c))
* **desktop:** survive a new login, and hand the engine over cleanly ([e6b0417](https://github.com/yuuki-kagura/adfree/commit/e6b0417b7480d69385ba224613843d8920444ba3))
* **dns:** an excepted page is resolved by the machine's own resolver ([2196805](https://github.com/yuuki-kagura/adfree/commit/2196805d3dfb5512449ca3aca0be2884f2e72063))
* **dns:** honor Android Private DNS and bound ECH exemptions ([74c6f66](https://github.com/yuuki-kagura/adfree/commit/74c6f66314af6cbe79e5f08f689d39902b5dc145))
* **filter:** an exception holds from the moment it exists, and only then ([a6366e2](https://github.com/yuuki-kagura/adfree/commit/a6366e23cc3aee5e838f4cfd6c20be97420c1b19))
* **filtering:** keep secure-DNS clients online and count TLS refusals ([8b82c38](https://github.com/yuuki-kagura/adfree/commit/8b82c3859c11d98377c968599d43a25f1e6962b8))
* **filter:** keep a page the user excepted excepted at the resolver ([a76bf32](https://github.com/yuuki-kagura/adfree/commit/a76bf32e2658153fa64daeb016f9832e44d94de1))
* **filter:** tie the exemption to the rules that granted it ([cfa8a13](https://github.com/yuuki-kagura/adfree/commit/cfa8a1325d04dafe7d15df7fc5d886093aa335c5))
* **lint:** make the tree pass `clippy --all-targets -D warnings` ([defd409](https://github.com/yuuki-kagura/adfree/commit/defd4098f81fef11d7caf89a80890168cab9a3b4))
* **log:** quieter type row, a readable destination, buttons that fit ([42cfad1](https://github.com/yuuki-kagura/adfree/commit/42cfad133fe22db6f68bbd353f35a6549afeb4be))
* **log:** the detail pane stops writing labels on top of values ([a7ecca7](https://github.com/yuuki-kagura/adfree/commit/a7ecca73b20e4d4d206a0b8acc50536bb2639f18))
* **mitm:** keep a blocked element blocked after a reload ([0f56802](https://github.com/yuuki-kagura/adfree/commit/0f568022509effee830d1a1304eb582ec043927b))
* **mitm:** splice apps whose TLS client rejects the certificate ([76cd14b](https://github.com/yuuki-kagura/adfree/commit/76cd14bff017376f2af99cd825a57bcefea05c2f))
* **mitm:** stop the browser from keeping an unfiltered copy of a page ([27adfcb](https://github.com/yuuki-kagura/adfree/commit/27adfcbddf525a2ae43c951694595f22d9640b02))
* **native-host:** match the answer by id instead of taking the first frame ([458e880](https://github.com/yuuki-kagura/adfree/commit/458e880459fdeb5049cc2f6efc73ed321ae40e90))
* **privileges:** leave a unit that is already filtering alone ([0303cac](https://github.com/yuuki-kagura/adfree/commit/0303cac17f0f8b0475d4c4b6dd597f1c969a8774))
* **privileges:** never build the unit from a command that cannot start itself ([2b8f5da](https://github.com/yuuki-kagura/adfree/commit/2b8f5da82311e4d89d263eb1e8a33dfc58a06865))
* **proxy:** close the flows an exception opened, once it ends ([c9421cc](https://github.com/yuuki-kagura/adfree/commit/c9421ccf6fae4ce6c867adc1b8cf7670ff20e4f4))
* **proxy:** keep writing to a peer past the first poll slice ([1fa2b91](https://github.com/yuuki-kagura/adfree/commit/1fa2b91aee37ed2f913da97489653a5d2cd45e35))
* **quic:** harden HTTP/3 routing for IPv6, MTU and bursts ([84d50b3](https://github.com/yuuki-kagura/adfree/commit/84d50b315a9ff142f38f7a15aa089d47befaf687))
* **scripts:** stop injecting a userscript tag when nothing is served ([474f730](https://github.com/yuuki-kagura/adfree/commit/474f7307898952f0a1cf0462950df16badd6d694))
* **settings:** usable light theme, independent DoT switch, config warnings ([21bb946](https://github.com/yuuki-kagura/adfree/commit/21bb946f7df4fa00ade27f5d79812526449ac121))
* **shell:** export NODE_USE_SYSTEM_CA with the extra CA ([061571b](https://github.com/yuuki-kagura/adfree/commit/061571b8d5c76c51e8159faf4f746c0ffe04dc90))
* **tray:** the mark follows filtering, not only the pause button ([1cf842b](https://github.com/yuuki-kagura/adfree/commit/1cf842b49ff830bbcf943eb6563240770e0e7328))
* **ui:** enlarge text and animate tab navigation ([25b8222](https://github.com/yuuki-kagura/adfree/commit/25b8222eeb927522abe3c69c447fa7575608c248))
* **ui:** make typed domains real rules and lift small text ([1056d36](https://github.com/yuuki-kagura/adfree/commit/1056d36242977d211207594678789d31441bfaf3))
* **vpn:** ask `isAlwaysOn` on the release that has it ([c911933](https://github.com/yuuki-kagura/adfree/commit/c9119330037b20d98cafdc20be579f0e8fbc02de))
* **vpn:** re-post the status notification and read MIUI's battery list ([4939384](https://github.com/yuuki-kagura/adfree/commit/4939384094744e240f9634495497f947d0de8cc0))


### Features

* **background:** refresh filters in the background and add the tile ([b691982](https://github.com/yuuki-kagura/adfree/commit/b6919827484612da7a290a8ba20eaf355211ccb4))
* **core:** a host for the AdGuard Assistant on the page ([1338ce0](https://github.com/yuuki-kagura/adfree/commit/1338ce020b8d2efa501245b3a0b1050f6a4d141f))
* **core:** a native-messaging host for AdGuard's browser extension ([a295c3f](https://github.com/yuuki-kagura/adfree/commit/a295c3f8ed06e980b18f51e42aad96eb7794a01e))
* **desktop:** a desktop body for the screens that looked like a phone ([e14c0e3](https://github.com/yuuki-kagura/adfree/commit/e14c0e3db0cb1035b505bd648d6e204a8260f440))
* **desktop:** answer AdGuard's browser extension from the window that filters ([e0145f9](https://github.com/yuuki-kagura/adfree/commit/e0145f9012bb8681d48aa5244082b8038d1356f8))
* **desktop:** install the assistant, and keep what it builds ([b672d27](https://github.com/yuuki-kagura/adfree/commit/b672d276864ccd4929e44ec66faf521c069da0fa))
* **desktop:** wire the tray into the window and the protection record ([c1eaefa](https://github.com/yuuki-kagura/adfree/commit/c1eaefac49aa94df950bae30ae2198d029aed189))
* **dns:** add a fallback resolver that defaults to system DNS ([7988bb0](https://github.com/yuuki-kagura/adfree/commit/7988bb0354373b473f550325238e553cd7ce74c7))
* **dns:** add encrypted upstreams and the DNS settings UI ([3146ac0](https://github.com/yuuki-kagura/adfree/commit/3146ac0b7c5ad63dceda8cbdbfbcdcfe4deeb5f4))
* **dns:** answer rewrites and SafeSearch in the resolver ([d0b9bcc](https://github.com/yuuki-kagura/adfree/commit/d0b9bcc199e377313c19c9004f8320a3e7edab7c))
* **dns:** block ECH by default off and log AdGuard-style endpoints ([02029b8](https://github.com/yuuki-kagura/adfree/commit/02029b84ad2c1b673bd32234c830b36c4d1f12ef))
* **extensions:** install the AdGuard Assistant switched off ([3b46b30](https://github.com/yuuki-kagura/adfree/commit/3b46b309fb682c63aa0bee78267d9a4af415b078))
* **http3:** expose Filter HTTP/3 in Android state, stats and settings ([964c4a6](https://github.com/yuuki-kagura/adfree/commit/964c4a64133d9c932bbeecdd3a31b5b20673454a))
* **i18n:** add in-app language selector ([3583aa3](https://github.com/yuuki-kagura/adfree/commit/3583aa3c9e35de1a1cbd4b4f17592153e4257a08))
* **i18n:** extract activity log strings ([14868cc](https://github.com/yuuki-kagura/adfree/commit/14868ccda1113727646bb7c78026c9b8f16b16bf))
* **i18n:** extract app firewall strings and stable category codes ([74197e6](https://github.com/yuuki-kagura/adfree/commit/74197e6f9a48e56d375a94b4530c8d6652cdcb15))
* **i18n:** extract filter, extension and rule-editor strings ([ece5586](https://github.com/yuuki-kagura/adfree/commit/ece5586385a809c15e3a6d1befa48babf5fb8f15))
* **i18n:** extract home, network, lab and hub strings ([273ee73](https://github.com/yuuki-kagura/adfree/commit/273ee7312ebdcbb5c30f8a3840f084cbbbca317a))
* **i18n:** extract settings, HTTPS and DNS strings ([25ba990](https://github.com/yuuki-kagura/adfree/commit/25ba990004349f3915ee7ab8b9774c657e3c0677))
* **i18n:** localize diagnostics through resource-backed UiText ([9c11799](https://github.com/yuuki-kagura/adfree/commit/9c11799131a9edc203981c0973400846c593c7a6))
* **i18n:** localize filter and userscript catalogues ([cc452c0](https://github.com/yuuki-kagura/adfree/commit/cc452c087c88bfbdd02f2f1c846fd8bf17b51f0f))
* **i18n:** localize security lab, notifications and DNS labels ([44e12e6](https://github.com/yuuki-kagura/adfree/commit/44e12e66000fb1dc35f034a5b1e38cc39955b7de))
* **log:** one toolbar, the way AdGuard's own log has one ([a5eb59e](https://github.com/yuuki-kagura/adfree/commit/a5eb59ec7688ba0a5913af9ffe6350742454d8f8))
* **log:** the desktop records the requests it allows ([b6b3a0b](https://github.com/yuuki-kagura/adfree/commit/b6b3a0b1baa0892f68ff294d5caee420267c161e))
* **log:** the log tab in the window opens the table, not the card stack ([40ceba9](https://github.com/yuuki-kagura/adfree/commit/40ceba9e06357701816d23dbc0b78cb586dce297))
* **page:** count what a page had blocked and badge it ([90e276d](https://github.com/yuuki-kagura/adfree/commit/90e276dc73f8c8d5e47d0337a93d92887a3ca658))
* **privileges:** ask the system once, not on every switch ([c698071](https://github.com/yuuki-kagura/adfree/commit/c698071e08771ae925f4fe63e55c16c54d4a2c3f))
* **privileges:** switching filtering on is how the privilege is asked for ([e74efcf](https://github.com/yuuki-kagura/adfree/commit/e74efcf5d48d41c4699e3161de642cafa5fdd32b))
* **proxy/scripts:** SOCKS5 UDP ASSOCIATE, auto routing, GM storage and menu ([613fae9](https://github.com/yuuki-kagura/adfree/commit/613fae97d5357021ef326473c774330d96ec9ce0))
* **quic:** add in-memory UDP transport for HTTP/3 termination ([d98a67e](https://github.com/yuuki-kagura/adfree/commit/d98a67e0dac8b8ee7b9c0dbbc654634d19530fdf))
* **quic:** apply content and header edits to HTTP/3 responses ([d0ca924](https://github.com/yuuki-kagura/adfree/commit/d0ca924251cafb7f016cf497bbc4973a7e3756b8))
* **quic:** route UDP/443 through an HTTP/3 filtering bridge ([7566324](https://github.com/yuuki-kagura/adfree/commit/756632461ee14d5a04a8fe80b1dbaa1f4004a236))
* **quic:** terminate and filter HTTP/3 requests in the MITM hub ([637c128](https://github.com/yuuki-kagura/adfree/commit/637c128c6bae3dd7f2a644138021d0e9d7c03e6e))
* **rules:** a rule builder, the way AdGuard for Windows has one ([1d84716](https://github.com/yuuki-kagura/adfree/commit/1d8471696b48168e160c01b90db5e793a7cffe15))
* **rules:** read a rule the way the builder needs to ([60611a2](https://github.com/yuuki-kagura/adfree/commit/60611a29329dd8c2eb8ee8ac793cd35ffd1db2b3))
* **settings:** add theme selection and a cosmetic filtering switch ([4348995](https://github.com/yuuki-kagura/adfree/commit/434899554702afe3eb7dfd381dd41d9a16b1e9c4))
* **state:** move persisted state into the Rust core ([fa54389](https://github.com/yuuki-kagura/adfree/commit/fa54389d6a317bec1cf2c805e22d1ed1430e96f1))
* **stealth:** wire stealth mode end to end ([6aed39b](https://github.com/yuuki-kagura/adfree/commit/6aed39bf67a7c527ae198981870288b47e6508ff))
* switch on the language filter that matches the device locale ([376948a](https://github.com/yuuki-kagura/adfree/commit/376948a0bbb1e2319df74ae840e80b3880d76cbe))
* **tray:** a real status icon and menu on KDE Wayland ([e602032](https://github.com/yuuki-kagura/adfree/commit/e602032541544f41e026c89f1ab5ba03263f3815))
* **trust:** install the MITM CA into the system store with root ([4d1870d](https://github.com/yuuki-kagura/adfree/commit/4d1870d32df04f0cdbff21e93b5f8a62af51cb57))
* **ui:** mirror AdGuard's Home dashboard and Protection module flow ([574054c](https://github.com/yuuki-kagura/adfree/commit/574054c9ef770a3c36544158d3ef40b485a0d513))
* **ui:** surface notification, battery and HTTPS health on Home ([5c54e70](https://github.com/yuuki-kagura/adfree/commit/5c54e7072c196c707657e625ecb1adcda40617a8))
* **ui:** unify row tiles and group the Settings tab ([9a6d1a7](https://github.com/yuuki-kagura/adfree/commit/9a6d1a79fa8216498fdde0d104fd7a2b3be81833))
* **vpn:** transient pause, WebRTC guard and hardened DNS transports ([95e9f0f](https://github.com/yuuki-kagura/adfree/commit/95e9f0fdca5be6e5afc25b253a1f8b70d1271f0e))


### Performance Improvements

* answer repeated DNS lookups from a bounded cache ([e4dc75c](https://github.com/yuuki-kagura/adfree/commit/e4dc75cf7cc12e2e50da312a630e116aac4457fa))
* bring the tunnel's DNS and idle cost to AdGuard's level ([6400fa2](https://github.com/yuuki-kagura/adfree/commit/6400fa231fd22aabd3638a5cedf1e06f02fa301a))
* build a flow's upstream half off the packet reader ([9210a10](https://github.com/yuuki-kagura/adfree/commit/9210a10fa37e4eb8a297804e4849274e95e3be0f))
* **ui:** stop the home hero from animating forever ([03345e8](https://github.com/yuuki-kagura/adfree/commit/03345e8645d117211aa785b9ee577d506042feb7))


### Reverts

* **page:** drop the per-page blocked badge ([673644f](https://github.com/yuuki-kagura/adfree/commit/673644fd78781d19be30eb2ebff2e40b5c72462e))

## [1.1.1](https://github.com/tachibana-shin/adfree/compare/v1.1.0...v1.1.1) (2026-10-26)


### Bug Fixes

* **android:** preserve JNA classes in release ([b6b7b59](https://github.com/tachibana-shin/adfree/commit/b6b7b59e33282223f7ccd5c0003f119b620eb67a))

# [1.1.0](https://github.com/tachibana-shin/adfree/compare/v1.0.0...v1.1.0) (2026-10-26)


### Features

* **apps:** enforce per-app network and screen-off rules ([9f03494](https://github.com/tachibana-shin/adfree/commit/9f0349488c088417247a4175274eb1e4089c2155))
* **filters:** add a help link and a store first-page control ([83f0053](https://github.com/tachibana-shin/adfree/commit/83f0053c79a80c1766576685d4977e7f27445099))
* **filters:** serve the deferred redirect resources ([4326eac](https://github.com/tachibana-shin/adfree/commit/4326eac21ca335d47338de6d4089bb072a5e0fb1))
* **filters:** split the tab into a filtering hub ([050cab3](https://github.com/tachibana-shin/adfree/commit/050cab34cbdc6be428ce884ad273f1e4d98e9b9f))
* **log:** attribute each request to the app that made it ([a85758b](https://github.com/tachibana-shin/adfree/commit/a85758b13716a39ef63d12fb9bd53990fe937296))
* **proxy:** route tcp flows through a socks5 endpoint ([802ebe9](https://github.com/tachibana-shin/adfree/commit/802ebe9eb0eb8404625668a0e2a2462185070741))

# 1.0.0 (2026-10-25)


### Bug Fixes

* **apps:** keep app row labels from wrapping on narrow screens ([106aef3](https://github.com/tachibana-shin/adfree/commit/106aef32c0b6af56d47e962bf01f28ac6f8c10a2))
* **core:** give the engine workers a 1 MiB stack ([6f3ad25](https://github.com/tachibana-shin/adfree/commit/6f3ad25e3e9d740e007179af2da1bc466b33f70c))
* **extensions:** scripts master defaults on with honest row state ([ba52865](https://github.com/tachibana-shin/adfree/commit/ba528650fba09bcd825dd9f8479b5967827153f6))
* **filter:** count the $match-case probes the crate refuses, and keep a streamed head first ([4791bf4](https://github.com/tachibana-shin/adfree/commit/4791bf4f1ed61272115a5f5810b5059e8a1f1666))
* **filters:** block invalid urls and surface download failures ([1945ea8](https://github.com/tachibana-shin/adfree/commit/1945ea818ef276cedc1598cfcf856c9bae30600c))
* **filters:** keep cosmetic rules and the user-rules sheet open ([21e1552](https://github.com/tachibana-shin/adfree/commit/21e1552e14cb8dae95f5df5638b81af5fb591fd2))
* **filters:** surface download errors and sync network toggles ([ef510aa](https://github.com/tachibana-shin/adfree/commit/ef510aa6e5f78bf1d7bb007a3634863d042f33fc))
* **mitm:** answer a HEAD with no body ([5bab19c](https://github.com/tachibana-shin/adfree/commit/5bab19c25cd27c89a1477eef8ed84110b278fa94))
* **mitm:** keep the head end right after a URL rewrite ([3d26a92](https://github.com/tachibana-shin/adfree/commit/3d26a92de646cedb14e781f7e94bc79a38b9cc89))
* **mitm:** make the TCP relay usable on device ([3bc105d](https://github.com/tachibana-shin/adfree/commit/3bc105de8184b622520bbef4262156acefa716c9))
* **mitm:** make the TLS splice actually carry HTTPS traffic ([c7b05e9](https://github.com/tachibana-shin/adfree/commit/c7b05e99ad56c74261ad22170b63224c0c9afb0e))
* **mitm:** never sign a leaf with a CA the user has not installed ([34116d9](https://github.com/tachibana-shin/adfree/commit/34116d913a8434cfb9defa651e0b9a6bf940fcdd))
* **mitm:** scope $urlblock to AdGuard's coverage and gate $removeparam ([9af1903](https://github.com/tachibana-shin/adfree/commit/9af190309a17be53e9ad14760e5720c9f2f4f91f))
* **mitm:** terminate public-name ECH unless full ECH is on ([322ca6c](https://github.com/tachibana-shin/adfree/commit/322ca6c183213586146c64cff1f06d9cac9cc210))
* **smart:** use or_default for retry-tracking entries ([f02252a](https://github.com/tachibana-shin/adfree/commit/f02252aea442912ad980e61542ced2bea5917392))
* **ui:** four layout faults found on device ([6bc4717](https://github.com/tachibana-shin/adfree/commit/6bc471732fad4190d7296946d12bb1d560decff7))
* **ui:** the power button disappeared when protection was off ([3175639](https://github.com/tachibana-shin/adfree/commit/317563911a4b984e53f1c401031b860957b61550))
* **vpn:** keep a second start from racing the tunnel build ([33c773e](https://github.com/tachibana-shin/adfree/commit/33c773e8bfec5966f98c5ada2e28fd663e35554d))
* **vpn:** keep adbd out of the tunnel ([eb38b24](https://github.com/tachibana-shin/adfree/commit/eb38b2483773ef4ae29b1c421dc3c000e89b2f58))


### Features

* **app:** require an installed certificate before HTTPS filtering ([7d6927a](https://github.com/tachibana-shin/adfree/commit/7d6927a0f0d24165092526015a97ffec98c6da7b))
* **apps:** add per-app HTTPS filtering ([6779aa1](https://github.com/tachibana-shin/adfree/commit/6779aa15803fdaa278983dc47662d28d6ddb8618))
* **apps:** apply per-app routing to the running tunnel ([2d64997](https://github.com/tachibana-shin/adfree/commit/2d64997f110357cbae28ab9a0959a497bf7396d9))
* **core:** move the settings blob into the Rust store ([b2ae314](https://github.com/tachibana-shin/adfree/commit/b2ae314138c17bba70b2d5df91fdadbcd922392e))
* **core:** own filters, scripts and the CA in Rust ([9481ebf](https://github.com/tachibana-shin/adfree/commit/9481ebf4720898e9018b9c88e83ff5a65ef17e71))
* **core:** Rust now owns the request log in SQLite ([e7fb2e4](https://github.com/tachibana-shin/adfree/commit/e7fb2e400ae8520c6bee641b9de9914cb6cc8d6f))
* **dns:** strip ECH so no client spends a handshake on it ([916e670](https://github.com/tachibana-shin/adfree/commit/916e670d4e0cb0c2801a56f4c6cd0ac5ee8dbba5))
* **engine:** enforce ad, tracking and DNS module switches ([c8f2b5a](https://github.com/tachibana-shin/adfree/commit/c8f2b5a9e3e69da126b9be2c1355f0f0c984c69d))
* **extensions:** import, create and edit userscripts ([7694f67](https://github.com/tachibana-shin/adfree/commit/7694f678b769f368e8cf7507b09ab17602ad8fac))
* **extensions:** show userscript header metadata and access warning ([5737471](https://github.com/tachibana-shin/adfree/commit/5737471a44631b5ed107f2496bf58d83464312e2))
* **filter:** add media and IMA redirect resources ([9e133d8](https://github.com/tachibana-shin/adfree/commit/9e133d8e6fc44f80f330bcd19e19d700a8ad1538))
* **filter:** add path-in-domain and app-scoped cosmetic rules ([66c23d5](https://github.com/tachibana-shin/adfree/commit/66c23d5454658ac08279c7e7a556b80441d0cea0))
* **filter:** anti-adblock — generic styles, detection redirects, AdFree Extra ([7ecaf49](https://github.com/tachibana-shin/adfree/commit/7ecaf49b30b84a381cca75732f4f70e5daaa5bcf)), closes [#sel](https://github.com/tachibana-shin/adfree/issues/sel)
* **filter:** cancel scoped style, procedural and scriptlet exceptions ([cb6c219](https://github.com/tachibana-shin/adfree/commit/cb6c219f24f6a25847c06a356247790341553723))
* **filter:** cut HLS playlist segments with $hls ([f9edff7](https://github.com/tachibana-shin/adfree/commit/f9edff71f56a9ed6a95afe931fc3e801b3e4db7a))
* **filter:** enforce $app= rules on TCP/HTTPS flows ([c0b8c72](https://github.com/tachibana-shin/adfree/commit/c0b8c729a357e2cb8a25cf8ece64df87abd3e8c7))
* **filter:** honor scoped cosmetic exceptions in main engine ([a1681fb](https://github.com/tachibana-shin/adfree/commit/a1681fbc9f317514be25c882a3513dcfa4f0a338))
* **filter:** honour the cosmetic exception modifiers ([cc8c6ef](https://github.com/tachibana-shin/adfree/commit/cc8c6ef1dce382522f858024ee8ec25c23bb8250))
* **filter:** HTML filtering ($$ / ##^) with $@$ exceptions ([13dd391](https://github.com/tachibana-shin/adfree/commit/13dd3919cf97d72711654fbdab0c2dcaf6c5b47e))
* **filter:** prune response JSON with $jsonprune ([770c869](https://github.com/tachibana-shin/adfree/commit/770c869fd657cebf5f8721839c1dfd8a6b419fa0))
* **filter:** rewrite response bodies with $replace rules ([ce4c0a8](https://github.com/tachibana-shin/adfree/commit/ce4c0a83f6b1b3125cfea5d2596ca4b750d1b74c))
* **filter:** run $urltransform and the $removeparam shapes the crate will not ([91faccf](https://github.com/tachibana-shin/adfree/commit/91faccf566dfa7a691a20cb5ba1662f3cf77c5ad))
* **filters:** add smart filtering for hosts stuck in retry loops ([67f03a2](https://github.com/tachibana-shin/adfree/commit/67f03a2c84c6615f7a168252b4440950fd79f661))
* **filters:** clear action, URL search and empty state ([887f6b0](https://github.com/tachibana-shin/adfree/commit/887f6b0f494a862c08a8488c265a0918208ce788))
* **filters:** confirm reset, edit and delete custom filters ([69f5574](https://github.com/tachibana-shin/adfree/commit/69f5574c0c414ae22da9cd44f5b34f039e63a14b))
* **filter:** serve AdGuard's $url location modifier ([6687071](https://github.com/tachibana-shin/adfree/commit/6687071e65c4574ff0fb3a9e5aa71bc0e94c372f))
* **filters:** expand catalogue with language and anti-adblock lists ([e2e0719](https://github.com/tachibana-shin/adfree/commit/e2e07196862d089aa41b660dbc041aa77bc2e4ac))
* **filter:** shape request and response headers with $csp, $permissions and $removeheader ([a924331](https://github.com/tachibana-shin/adfree/commit/a9243319f94d141b981f3b77f757168a826298ab))
* **filters:** import and export user rules ([ed2d890](https://github.com/tachibana-shin/adfree/commit/ed2d890657a7d301e7a9c93900349a1ce1d352b4))
* **filters:** mark module-gated groups inactive with enable action ([2cc60c3](https://github.com/tachibana-shin/adfree/commit/2cc60c323c007ce41a072c935bc51e340b353976))
* **filters:** refresh stale lists on resume and clarify app presets ([7925349](https://github.com/tachibana-shin/adfree/commit/7925349584b6dfdfb2c16ccd303a14ade8d550e6))
* **filters:** refresh stale subscriptions on launch ([ddf046d](https://github.com/tachibana-shin/adfree/commit/ddf046d850564cfe621a08fb666251382cbb047b))
* **filters:** serve the stitched userscript over the splice ([e6a488d](https://github.com/tachibana-shin/adfree/commit/e6a488d43d1f8f2dab161d576664c02f5b2be3ec))
* **filters:** show size, build state and source actions in detail sheet ([a67fba9](https://github.com/tachibana-shin/adfree/commit/a67fba9e40e0ef5147c83cd2a6b82ac47861f323))
* **filters:** surface per-list engine build errors ([2a09d3c](https://github.com/tachibana-shin/adfree/commit/2a09d3ca2f9feda325b7878db05b459572dede42))
* **filters:** whitelist tab, validated DNS and app-log consistency ([dedafc2](https://github.com/tachibana-shin/adfree/commit/dedafc288a2ada748172664bff0c89d05f4603c8))
* **filter:** take the cookies $cookie names off both halves of a request ([3277dff](https://github.com/tachibana-shin/adfree/commit/3277dff06ca9d72ded9fc07f285edcdb1fad5f8d))
* **filter:** trusted-filters gate + raw #%# JavaScript rules ([c7128c7](https://github.com/tachibana-shin/adfree/commit/c7128c7d41f86f58be89417b648feed393461283))
* **https:** let users exclude or isolate sites from TLS decryption ([53da7ef](https://github.com/tachibana-shin/adfree/commit/53da7ef1f0c978e228f3e50042ed90bb093e21f8))
* **https:** show when the local CA expires ([f0dcfba](https://github.com/tachibana-shin/adfree/commit/f0dcfba27949339734231d35196df6ec1084875c))
* initialize project structure and base UI ([0e5ce75](https://github.com/tachibana-shin/adfree/commit/0e5ce75b945b535b39c47bb89b346d2b0373dfa7))
* **mitm:** add an opt-in full-ECH switch for clients that hide their names ([f42c4c8](https://github.com/tachibana-shin/adfree/commit/f42c4c818bb23b173874c4ff1b359f8f338ed0e9))
* **mitm:** answer a request that carries a body ([af8cd6e](https://github.com/tachibana-shin/adfree/commit/af8cd6eb33d82ce011a0d0a8fbcac3a78f0cde44))
* **mitm:** apply the URL-scoped network rules in the tunnel ([67f470e](https://github.com/tachibana-shin/adfree/commit/67f470efdd35ba1e9382645d4f933e1aa7290fd1))
* **mitm:** decide interception from the ClientHello SNI, not the DNS map ([1c14ba5](https://github.com/tachibana-shin/adfree/commit/1c14ba5798ef775d57dbc553490ec84d9d2f95ff))
* **mitm:** filter page cosmetics, streaming bodies too big to hold ([0f3a4d0](https://github.com/tachibana-shin/adfree/commit/0f3a4d0ea1deaf49c142dd637baef53e9579151c))
* **mitm:** HTTPS filtering stage (CA, script injection, TLS splice) ([ece15aa](https://github.com/tachibana-shin/adfree/commit/ece15aa68a9eb9f4521f2f7334ca792d7f93d45e))
* **mitm:** inject early in <head> and serve the assets from our own origin ([de7f7b3](https://github.com/tachibana-shin/adfree/commit/de7f7b3a010bcd66366c5e9086b352f6d3198dad))
* **mitm:** keep the page's CSP and inject with a per-response nonce ([9913615](https://github.com/tachibana-shin/adfree/commit/991361566fdb43ad193ae0548f163d03b6989658))
* **mitm:** modernize the page runtime and test it in a real browser ([5b92351](https://github.com/tachibana-shin/adfree/commit/5b9235133f851b37eb214642db4fde8919d64df0))
* **mitm:** offer the host's own ECH upstream, so ECH-required hosts stay filterable ([bf77681](https://github.com/tachibana-shin/adfree/commit/bf77681330fb3308abc983cdb88845076db3784c))
* **mitm:** serve element hiding as a stylesheet the browser caches ([9a66dac](https://github.com/tachibana-shin/adfree/commit/9a66dacb32688b66c8cfba15178b0b0ed851432a))
* **mitm:** splice only real ECH, gated on the learned public name ([aa73672](https://github.com/tachibana-shin/adfree/commit/aa736721d6db38f6d986568768305c37e3e9557d))
* **mitm:** wire the relay into the packet engine ([1c2f83c](https://github.com/tachibana-shin/adfree/commit/1c2f83cfa97a970e55a35e9572eeff44f597abbd))
* **relay:** carry every TCP flow, not only HTTPS ([2916dc0](https://github.com/tachibana-shin/adfree/commit/2916dc0d1f5616d2788909ad4d45440c4a9330e0))
* **relay:** NAT every non-DNS UDP flow through protected sockets ([7ce188a](https://github.com/tachibana-shin/adfree/commit/7ce188a3fbdd4edf4047b7544bae24a5c5bcaae1))
* Rust core with real AdGuard engine, uniffi bridge, and MITM stage ([f551f83](https://github.com/tachibana-shin/adfree/commit/f551f832b7e691406435443483a497fe9435e5f5))
* **settings:** add backup and restore of settings and filters ([5b1049b](https://github.com/tachibana-shin/adfree/commit/5b1049b9868d3b0cc4ffb0aca0ebd7ac0da959e3))
* **settings:** persist app firewall and DNS choices ([bb3cd23](https://github.com/tachibana-shin/adfree/commit/bb3cd23282b55f69366fb6c8a614b2e93fd0968a))
* **ui:** keep protection and HTTPS filtering across restarts ([ff3a381](https://github.com/tachibana-shin/adfree/commit/ff3a381812da1c8f1bd7f917fe549e03230a83ba))
* **ui:** read the request log from SQLite with paging and clear ([cd7595f](https://github.com/tachibana-shin/adfree/commit/cd7595f8efe05a98c77748aca8153a888a4f1506))
* **userscripts:** add Tampermonkey metadata and Greasy Fork store ([4e1fc9d](https://github.com/tachibana-shin/adfree/commit/4e1fc9d58f894311c3ba04fefc86031e699de4d5))
* **userscripts:** paginate and sort the Greasy Fork store ([316fb73](https://github.com/tachibana-shin/adfree/commit/316fb731f82c1f8f344debdcc47e944e439b68c0))
* **userscripts:** support [@require](https://github.com/require) and safe GM APIs ([84159a1](https://github.com/tachibana-shin/adfree/commit/84159a1742d9377fe556d8abaee358e7345c0931))


### Performance Improvements

* **engine:** park the forwarder on descriptors, not on the clock ([8ff7b64](https://github.com/tachibana-shin/adfree/commit/8ff7b64e23d7c103060af0922997c39f2d7d4079))
* **mitm:** bound relay buffering and reuse HTML plans ([31ca508](https://github.com/tachibana-shin/adfree/commit/31ca5081ad189a52131d8aa20884e4e9c9bc0f4b))
