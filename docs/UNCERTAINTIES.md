# Points à valider sur un tenant réel

Le code a été testé contre une API XC simulée qui suit la référence publiée. Les points
ci-dessous ne sont pas entièrement spécifiés dans la documentation et doivent être
vérifiés sur un tenant de test (token en lecture seule d'abord).

1. **Champs des security events et access logs.** L'API renvoie chaque événement sous
   forme de chaîne JSON dont le schéma n'est pas publié. La liste conservée
   (`sanitize.EVENT_FIELDS`, `ACCESS_LOG_FIELDS`) reprend les noms usuels de la console.
   Un champ absent est simplement ignoré. Le compteur `_dropped_fields` aide à repérer
   ce qui manque.
2. **Filtres des security events.** La référence documente `vh_name`, `src_site`,
   `city` et `country`, plus `app_type` en exemple. Les autres filtres (`src_ip`,
   `sec_event_type`, `action`...) sont déduits des clés d'agrégation documentées.
3. **Forme de réponse avec `GET_RSP_FORMAT_FOR_REPLACE`.** Le code lit `replace_form`
   (metadata + spec). S'il est absent, il retombe sur `metadata`/`spec` de la réponse.
   Un replace avec des champs en lecture seule peut être refusé par XC (erreur 400
   renvoyée proprement).
4. **Clé `waf_mode` dans les événements**, et forme exacte d'une règle d'exclusion
   suggérée par XC : à vérifier avec un vrai faux positif.
5. **Pagination des listes.** Les opérations List n'ont pas de pagination documentée
   (seulement `label_filter` / `report_fields`). Le serveur tronque à
   `F5XC_MCP_MAX_ITEMS` et l'indique (`truncated: true`).
