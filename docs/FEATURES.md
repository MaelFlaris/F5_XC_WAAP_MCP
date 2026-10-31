# Fonctionnalités F5 Distributed Cloud WAAP et couverture du serveur MCP

Liste établie à partir de la référence API officielle
(<https://docs.cloud.f5.com/docs-v2/api>, 283 objets publiés). Chaque page de la
référence embarque la spécification OpenAPI de l'objet. Les chemins utilisés par le
serveur en sont extraits par `scripts/generate_catalog.py` : aucun endpoint n'est
deviné.

Légende :

- **L** : lecture (outils `list_objects` / `get_object` ou outil dédié) ;
- **É** : écriture via plan → confirmation humaine → apply (mode write uniquement). « É (outil) » = modification ciblée ; « É (création) » = création d'un objet neuf seulement ;
- **—** : pas couvert pour l'instant (feuille de route) ;
- **🔒** : peut contenir des secrets, seule la vue résumé est disponible.

## 1. Load balancing et publication d'applications

| Fonctionnalité XC | Objet API | Couverture |
|---|---|---|
| HTTP/HTTPS Load Balancer (domaines, TLS auto-cert, routes, pools, publication) | `views.http_loadbalancer` | L, posture sécurité, infos DNS ; É (outil) : WAF attaché, exclusions WAF |
| TCP Load Balancer | `views.tcp_loadbalancer` | L |
| CDN Load Balancer | `views.cdn_loadbalancer` | L |
| UDP Load Balancer | `views.udp_loadbalancer` | — |
| Origin pools (serveurs d'origine, TLS vers l'origine, algorithme) | `views.origin_pool` | L |
| Health checks | `healthcheck` | L, É (création) |
| Certificats TLS, chaînes intermédiaires, listes de CA | `certificate`, `certificate_chain`, `trusted_ca_list` | L 🔒 / L / L |
| Expiration des certificats (CN, SAN, émetteur, jours restants, LB utilisateurs, certificats automatiques des LB) | `certificate.infos`, `auto_cert_info` du LB | L (`list_certificate_expiry`), sans jamais lire la clé privée |
| Règles de cache CDN | `cdn_cache_rule` | L |
| BIG-IP Virtual Servers publiés via XC | `views.bigip_virtual_server` | L |
| Adresses IP publiques (VIP exposées) | `public_ip` | L |
| Purge de cache CDN | `cdn_loadbalancer/.../cache-purge` | — (action destructive, volontairement non exposée) |
| Virtual hosts (objets bas niveau) | `virtual_host` | — |

## 2. Web Application Firewall

| Fonctionnalité XC | Objet / API | Couverture |
|---|---|---|
| App Firewall : mode blocking / monitoring, signatures, violations, bot setting, IA, anonymisation | `app_firewall` | L, É (outil) `plan_set_waf_mode`, É (création) |
| Attacher / détacher un WAF à un LB | champ `waf_choice` du LB | `plan_set_lb_waf` |
| Exclusions WAF (faux positifs) inline ou en policy | `waf_exclusion` du LB, `waf_exclusion_policy` | L, `suggest_waf_exclusion_rule` ; É (outil) `plan_add_waf_exclusion_rule` (règles inline) ; É (création) pour une policy |
| Version des signatures d'attaque | `/api/waf/latest-signatures-version` | L |
| Signatures staged / released par virtual host, threat campaigns | `waf_signatures_changelog` | — |
| Hits par règle WAF (tri des faux positifs) | `wafs/metrics/server/rule_hits` | L (`get_waf_rule_hits`) |

## 3. Policies (contrôle d'accès, débit)

| Fonctionnalité XC | Objet API | Couverture |
|---|---|---|
| Service policies (allow/deny par IP, pays, ASN, en-têtes, chemins...) | `service_policy` | L, É (création) |
| Service policies actives au niveau namespace | `active_service_policies` | L |
| Service policy sets | `service_policy_set` | L |
| Règles legacy de service policy | `service_policy_rule` | L |
| Rate limiter policies et rate limiters | `views.rate_limiter_policy`, `rate_limiter` | L, É (création) |
| Listes d'IP (blocklist / allowlist) | `ip_prefix_set` | L, É (outil) `plan_update_ip_prefix_set`, É (création) |
| Forward proxy policies, policers | `views.forward_proxy_policy`, `policer`, `protocol_policer` | L |
| Network firewall, enhanced firewall, Fast ACL (sites CE) | `network_firewall`, `enhanced_firewall_policy`, `fast_acl` | L |

## 4. Bot defense, utilisateurs malveillants, client-side

| Fonctionnalité XC | Objet API | Couverture |
|---|---|---|
| Bot defense standard du LB (activée / désactivée) | `bot_defense_choice` du LB | L (posture) |
| Infrastructure Bot Defense avancée | `views.bot_defense_app_infrastructure` | L |
| Bot Defense avancé (Shape) : protected apps, allowlists, endpoints, reporting (~120 opérations) | `shape_bot_defense_*` | — (seulement si l'offre avancée est utilisée) |
| Détection d'utilisateurs malveillants, identification, mitigation | `malicious_user_mitigation`, `user_identification`, `app_setting`, `app_type` | L |
| Logs d'utilisateurs suspects | `app_security/suspicious_user_logs` | L (`query_suspicious_users`) |
| Client-side defense (Shape) | `shape_client_side_defense_*` | — (posture LB seulement) |
| IP reputation, threat mesh, challenges JS/captcha | champs du LB | L (posture) |

## 5. Sécurité des API

| Fonctionnalité XC | Objet API | Couverture |
|---|---|---|
| Définitions d'API (OpenAPI), inventaire | `views.api_definition` | L |
| Groupes d'API | `views.app_api_group` | L |
| API discovery (configuration) | `api_discovery` | L |
| API crawler, API testing | `api_crawler`, `api_testing` | L 🔒 |
| Sensitive data policies, data types | `sensitive_data_policy`, `data_type` | L |
| Endpoints découverts, swagger appris, mises à jour de schéma | `/api/ml/data/.../api_endpoints` | — |
| Validation OpenAPI, JWT, protection d'endpoints | champs du LB | L (posture / spec) |

## 6. DDoS

| Fonctionnalité XC | Objet / API | Couverture |
|---|---|---|
| Protection L7 DDoS, règles d'auto-mitigation | LB + `dos_automitigation_rules` | L (`get_lb_dos_mitigation_rules`, posture) |
| Slow DDoS (timeouts) | champ du LB | L (posture) |
| Seuil RPS L7 DDoS | `l7ddos_rps_threshold` | — |
| Routed DDoS L3/L4 (InfraProtect) | `infraprotect_*` | — |

## 7. Observabilité et investigation

| Fonctionnalité XC | API | Couverture |
|---|---|---|
| Security events (WAF, bot, API, service policy) | `app_security/events` | L (`query_security_events`) |
| Agrégations (top signatures, IP, pays, LB...) | `app_security/events/aggregation` | L (`aggregate_security_events`) |
| Security incidents | `app_security/incidents` | L |
| Access logs et agrégations | `access_logs`, `access_logs/aggregation` | L |
| Audit logs (qui a modifié quoi) | `audit_logs` | L (`query_audit_logs`) |
| Alert policies, alert receivers, global log receivers | `alert_policy`, `alert_receiver`, `global_log_receiver` | L / L 🔒 / L 🔒 |
| Alertes actives, historique | `alerts` | L (`list_alerts`, `query_alerts_history`) |
| Suggestions XC (block client, trust client, rate limit, DDoS, OAS, `api_sec/rule_suggestion`) | `.../suggestion` | WAF exclusion seulement ; les autres en feuille de route (aucun outil d'écriture ne les exploiterait) |

## 8. DNS

| Fonctionnalité XC | Objet API | Couverture |
|---|---|---|
| Zones DNS primaires / secondaires | `dns_zone` | L |
| DNS load balancer, pools, health checks, geo location sets | `dns_load_balancer`, `dns_lb_pool`, `dns_lb_health_check`, `geo_location_set` | L |

## Volontairement absent

- **Suppression** d'objets, de namespaces ou de sites. Aucun outil ne le permet, en aucun mode.
- **Outil générique** de requête API (« raw request »). Seuls les chemins du catalogue fermé sont appelables.
- **Écriture** dans les namespaces `system`, `shared` et `ves-io-shared`.
- **Remplacement générique** de la spec d'un objet. Les écritures passent par des outils
  ciblés (WAF d'un LB, mode du WAF, listes d'IP, exclusions WAF). La création est
  limitée aux objets sans effet tant qu'ils ne sont pas référencés. Les autres
  modifications (routes, origin pools, bot defense, API discovery...) sont en feuille de
  route, chacune avec un outil dédié.
- Objets d'administration du tenant (utilisateurs, rôles, credentials API, tenant management).
