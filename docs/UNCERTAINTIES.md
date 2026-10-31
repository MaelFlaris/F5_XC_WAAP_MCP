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
5. **`whoami` avec un token API — à tester en premier, dépendance critique.** La
   référence décrit cet appel comme basé sur le « username header from the request
   context ». Il faut vérifier, avec `f5xc-waap-mcp check` :
   - qu'il renvoie bien le propriétaire d'un **API token** (pas seulement d'une session
     console) ; sinon personne ne peut s'authentifier (`identity_unavailable`) ;
   - qu'un rôle limité aux namespaces applicatifs peut l'appeler sur
     `namespaces/system` ; un 403 est remonté en `identity_unavailable`, sans cache ;
   - quels champs (`email`, `user_uuid`, `type`) sont remplis pour un token personnel
     et pour une service credential.
6. **Vérifié depuis dans la spec brute** (`docs/evidence/openapi-facts.json`) : le PUT
   n'a aucune précondition de version ; le replace réécrit `labels`, `annotations`,
   `description` et `disable` ; les champs de `app_firewall_detection_control` ; le schéma
   de réponse de `whoami` contient `name`, `email`, `user_uuid` et `type`. Reste à
   vérifier sur un tenant que `whoami` les **remplit** pour un token API.
7. **Références vers des objets inexistants.** La recherche avant création suppose que
   XC accepte qu'un LB ou une policy référence un objet qui n'existe pas encore (le
   format de réponse `GET_RSP_FORMAT_BROKEN_REFERENCES` le suggère). La liste des types
   référents (`REFERENCERS` dans `tools/changes.py`) est à valider.
8. **Métriques de performance (`get_lb_performance`).** Le sens `downstream` / `upstream`
   pour un nœud « virtual host » n'est pas précisé dans la référence : l'outil demande les
   deux et les renvoie séparément. Le nom de virtual host d'un LB HTTP (`ves-io-http-loadbalancer-<nom>`)
   et le format des alertes (`data` est typé chaîne) sont aussi à confirmer sur un tenant.
9. **Pagination des listes.** Les opérations List n'ont pas de pagination documentée
   (seulement `label_filter` / `report_fields`). Le serveur tronque à
   `F5XC_MCP_MAX_ITEMS` et l'indique (`truncated: true`).
