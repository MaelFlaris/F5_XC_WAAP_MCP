# f5xc-waap-mcp

Serveur MCP (Model Context Protocol) pour **F5 Distributed Cloud WAAP**. Il couvre les
load balancers, le WAF, les policies, le bot defense, la sécurité des API, les security
events et les logs. Il est sécurisé par conception :

- **lecture seule par défaut** ;
- les écritures passent par un **plan** (diff exhaustif calculé côté serveur), puis une
  **confirmation humaine** qui affiche ce diff complet et le hash du corps envoyé
  (MCP elicitation), puis l'**application** ;
- **aucune suppression**, **aucun remplacement générique** et **aucun outil de requête
  générique** ;
- l'**identité est nominative** : chaque token est résolu en utilisateur XC (`whoami`)
  avant tout appel.

Les endpoints viennent de la référence API officielle (`data/catalog.json`, généré par
`scripts/generate_catalog.py` à partir des spécifications OpenAPI publiées sur
docs.cloud.f5.com).

- Liste des fonctionnalités couvertes : [docs/FEATURES.md](docs/FEATURES.md)
- Modèle de menaces : [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- Points à valider sur un tenant : [docs/UNCERTAINTIES.md](docs/UNCERTAINTIES.md)

## Outils

**Lecture (toujours disponibles)**

| Outil | Rôle |
|---|---|
| `list_supported_kinds` | Les 40 types d'objets couverts, par famille, avec le lien vers la doc |
| `list_namespaces` | Namespaces autorisés |
| `list_objects(kind, namespace)` | Liste d'un type d'objet (LB, origin pools, WAF, service policies, rate limiters, API definitions, zones DNS...) |
| `get_object(kind, namespace, name, view)` | `summary` (options configurées et références), `spec` (secrets masqués) ou `referrers` (qui utilise l'objet) |
| `get_active_service_policies` | Service policies actives au niveau du namespace |
| `get_lb_security_posture` | Protections actives d'un LB HTTP (WAF et son mode, bot, API discovery, IP reputation, rate limit, DDoS, TLS...) avec des constats classés par sévérité |
| `audit_namespace_security` | La même posture pour tous les LB HTTP d'un namespace |
| `query_security_events` / `aggregate_security_events` | Security events filtrés, top signatures / IP / pays / LB |
| `query_security_incidents`, `query_suspicious_users` | Incidents, utilisateurs suspects |
| `query_access_logs` / `aggregate_access_logs` | Access logs et agrégations (codes de réponse, chemins...) |
| `query_audit_logs` | Qui a modifié quoi dans le namespace |
| `suggest_waf_exclusion_rule` | Règle d'exclusion proposée par XC pour un faux positif |
| `get_lb_dos_mitigation_rules`, `get_lb_dns_info`, `get_waf_signatures_version` | DDoS auto-mitigation, infos DNS du LB, version des signatures |

**Écriture (seulement avec `F5XC_MCP_MODE=write` et `F5XC_MCP_ENABLE_WRITES=true`)**

| Outil | Rôle |
|---|---|
| `plan_set_lb_waf` | Attacher (ou retirer) un App Firewall sur un LB |
| `plan_set_waf_mode` | Passer un WAF en blocking ou en monitoring |
| `plan_update_ip_prefix_set` | Ajouter ou retirer des IP d'une liste (blocage, allowlist) |
| `plan_add_waf_exclusion_rule` | Ajouter une exclusion WAF (faux positif). Les règles qui désactivent tout le WAF sont refusées |
| `plan_create_object` | Créer un objet sans effet tant qu'il n'est pas référencé : App Firewall, service policy, ip_prefix_set, rate limiter, WAF exclusion policy, health check |
| `apply_plan(plan_id)` | Applique un plan après confirmation humaine |
| `plan_revert(plan_id)` | Prépare le retour à l'état d'avant un replace appliqué (si `F5XC_MCP_ROLLBACK_DIR` est défini) ; plan revu comme les autres, avec l'auteur d'origine ; HIGH RISK si ce n'est pas vous. Les secrets ne sont jamais écrits dans le fichier : ils sont repris de l'objet actuel |

### Ce que voit la personne qui confirme

Le message d'élicitation est construit par le serveur, pas par le modèle. Il contient :

- un bandeau `!!! HIGH RISK !!!` avec les raisons quand le changement baisse la
  protection : WAF désactivé ou passé en monitoring, WAF attaché en monitoring,
  bot / IP reputation / rate limit désactivés, trusted clients modifiés, modification
  d'un `ip_prefix_set` (qui peut servir d'allowlist), création d'un objet déjà référencé
  (il devient actif immédiatement) ou dont la recherche de références est incomplète ;
- pour les exclusions WAF, chaque règle nouvelle ou modifiée est évaluée. Elle n'est
  « standard » que si elle exclut des signatures précises sur un domaine et un chemin
  précis. Sinon elle est HIGH RISK : `any_domain`, `any_path`, domaine ou chemin absent,
  `path_regex`, exclusion de types d'attaque, de violations ou de bots, `signature_id`
  0, ou `waf_skip_processing` ;
- la cible, la requête (`PUT /api/config/...`) et le **SHA-256 du corps** envoyé ;
- le **diff complet**, feuille par feuille. Les règles nommées sont appariées par nom et
  un changement d'ordre est signalé. Les valeurs sont échappées en JSON (caractères de
  contrôle ou invisibles visibles), jamais tronquées.

Pour confirmer, il faut retaper le nom de l'objet. En cas de HIGH RISK, il faut aussi
retaper les 8 premiers caractères du hash.

Un diff qui ne peut pas être montré en entier est refusé au moment du plan : plus de 80
champs, une valeur de plus de 300 caractères ou plus de 8 000 caractères au total. Il
faut alors découper le changement. Un changement qui touche un champ secret (clé
privée, mot de passe, token...) est refusé.

Un plan est à usage unique, lié à l'utilisateur XC qui l'a créé, et expire après
5 minutes.

Il est refusé si l'objet a changé entre le plan et l'application. Le contrôle couvre la
spec, les métadonnées réécrites par le PUT (`labels`, `annotations`, `description`,
`disable`) et l'`uid`, ce qui détecte un objet supprimé puis recréé.

L'API XC publiée n'offre pas de précondition de version sur le PUT. Il reste donc une
fenêtre courte entre la relecture de contrôle et le PUT ; voir le modèle de menaces.

Les namespaces `system` et `shared` ne sont jamais modifiés.

## Installation

```bash
python -m venv .venv && . .venv/bin/activate
pip install --require-hashes -r requirements-dev.lock
pip install --require-hashes -r requirements-build.lock
pip install --no-deps --no-build-isolation .
pytest                                              # tests + propriétés Hypothesis
python -I scripts/mutate_guards.py . mutation.json  # chaque garde-fou doit être tué par les tests
```

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `F5XC_TENANT` | (obligatoire) | Identifiant court du tenant : `https://<tenant>.console.ves.volterra.io` |
| `F5XC_ALLOWED_NAMESPACES` | (obligatoire) | Liste séparée par des virgules ; tout autre namespace est refusé |
| `F5XC_API_TOKEN` | — | stdio uniquement : **ton** token API personnel. Interdit en mode HTTP |
| `F5XC_MCP_MODE` | `read` | `read` ou `write` |
| `F5XC_MCP_ENABLE_WRITES` | `false` | Doit aussi valoir `true` pour activer l'écriture |
| `F5XC_MCP_TRANSPORT` | `stdio` | `stdio` ou `streamable-http` |
| `F5XC_MCP_BIND_HOST` / `_PORT` | `127.0.0.1` / `8765` | Loopback par défaut (reverse proxy TLS devant) |
| `F5XC_MCP_ALLOW_NON_LOOPBACK_BIND` | `false` | Autorise un bind hors loopback (conteneur). Exige le mode HTTP et `F5XC_MCP_ALLOWED_HOSTS` |
| `F5XC_MCP_ALLOWED_HOSTS` / `_ORIGINS` | localhost | Valeurs `Host` et `Origin` acceptées (anti DNS rebinding) |
| `F5XC_MCP_CA_BUNDLE` | — | CA supplémentaire (proxy d'entreprise) ; la vérification TLS ne peut pas être désactivée |
| `F5XC_MCP_HTTPS_PROXY` | — | Proxy sortant vers XC (`http(s)://hôte:port`, sans identifiants). `HTTPS_PROXY` n'est **pas** lu |
| `F5XC_MCP_WRITE_KILL_SWITCH` | — | Chemin d'un fichier : tant qu'il existe, toute écriture est refusée, y compris un `apply_plan` déjà en cours de confirmation (sans redémarrage) |
| `F5XC_MCP_ROLLBACK_DIR` | — | Répertoire (`0700`) où l'état « avant » de chaque replace appliqué est gardé (`0600`) pour `plan_revert` |
| `F5XC_MCP_RATE_PER_MINUTE` / `_GLOBAL_RATE_PER_MINUTE` | 60 / 300 | Limites de débit |
| `F5XC_MCP_MAX_EVENTS`, `_MAX_ITEMS`, `_MAX_QUERY_WINDOW_H` | 100, 200, 168 | Bornes des réponses |
| `F5XC_MCP_PLAN_TTL_S` | 300 | Durée de vie d'un plan |
| `F5XC_MCP_MIN_IPV4_PREFIX_LEN` | 16 | Préfixe minimum accepté dans un `ip_prefix_set` (`/0`, `/8`... refusés) |
| `F5XC_MCP_IDENTITY_CACHE_TTL_S` | 300 | Cache de la résolution token → utilisateur |
| `F5XC_MCP_AUTH_RATE_PER_MINUTE` | 30 | Validations de tokens inconnus par minute (tous clients confondus) |
| `F5XC_MCP_ALLOW_SERVICE_CREDENTIALS` | `false` | Accepte les service credentials (comptes non nominatifs) |
| `F5XC_MCP_AUDIT_LOG` | stderr | Fichier du journal d'audit JSON (créé en `0600`, compatible logrotate) |

### Premier test sur un tenant : `f5xc-waap-mcp check`

À lancer **avant toute mise en service**, avec le token personnel d'un utilisateur qui a
le rôle prévu pour le serveur :

```bash
F5XC_TENANT=acme-corp F5XC_ALLOWED_NAMESPACES=prod,staging F5XC_API_TOKEN=... f5xc-waap-mcp check
```

La commande appelle `whoami` et indique quels champs sont remplis (`name`, `email`,
`user_uuid`, `type`) et l'identité retenue. Puis, pour chaque namespace autorisé, elle
indique si le rôle peut lister les LB HTTP et lire les service policies actives. Elle
n'écrit rien et n'affiche jamais le token. Code de sortie 1 si l'identité ne peut pas
être résolue : dans ce cas, le serveur refusera tous les appels.

### Token, identité et droits

Crée un **token API personnel** dans la console XC (Account > Credentials). Le serveur
le résout en utilisateur avec `GET /api/web/custom/namespaces/system/whoami` avant tout
autre appel :

- l'audit et les quotas utilisent le nom, l'e-mail et l'UUID XC, pas le token ;
- une rotation de token ne change donc pas l'identité ;
- un token refusé par XC (401) est mis en cache négatif 60 s et ne consomme aucun
  quota. Un 403 sur `whoami` (rôle qui ne peut pas lire le namespace `system`) donne
  l'erreur `identity_unavailable`, sans cache négatif : une correction du rôle
  s'applique tout de suite ;
- les validations de tokens inconnus sont limitées globalement ;
- les service credentials sont refusées par défaut.

Les droits du serveur sont ceux de ton rôle XC : commence avec un rôle en lecture sur
les namespaces concernés, et ne passe à un rôle d'écriture que pour le mode write.
Le journal d'audit XC (`query_audit_logs`) reste le contrôle compensatoire, côté F5.

### Claude Code (stdio)

`.mcp.json`. Le token est lu depuis ton environnement, jamais écrit dans le fichier :

```json
{
  "mcpServers": {
    "f5xc-waap": {
      "command": "f5xc-waap-mcp",
      "env": {
        "F5XC_TENANT": "acme-corp",
        "F5XC_ALLOWED_NAMESPACES": "prod,staging",
        "F5XC_API_TOKEN": "${F5XC_API_TOKEN}"
      }
    }
  }
}
```

### Mode HTTP (multi-utilisateur)

```bash
F5XC_TENANT=acme-corp F5XC_ALLOWED_NAMESPACES=prod F5XC_MCP_TRANSPORT=streamable-http \
F5XC_MCP_ALLOWED_HOSTS=mcp.example.com F5XC_MCP_ALLOWED_ORIGINS=https://mcp.example.com \
f5xc-waap-mcp
```

Chaque client envoie son propre token dans l'en-tête `X-F5XC-API-Token`. Le serveur
n'a pas de token à lui. Termine le TLS sur un reverse proxy devant `127.0.0.1:8765`,
et **limite le débit par IP sur ce proxy** : le serveur limite les validations de
tokens inconnus, mais il ne voit que l'IP du proxy.

### Conteneur

L'image est construite à partir d'une base Debian 13 (trixie) épinglée par digest. Les
dépendances sont vérifiées par hash, elle tourne en utilisateur non-root (UID 65532), sans
outil de build ni pip. La CI la scanne avec Trivy et échoue sur toute vulnérabilité
HIGH/CRITICAL corrigeable.

```bash
docker build -t f5xc-waap-mcp .
```

Deux façons de l'exposer :

- **proxy dans le même namespace réseau** (sidecar dans un pod, ou
  `--network container:<proxy>`) : le serveur reste en `127.0.0.1`, sans configuration
  de plus ;
- **bind explicite**, quand le proxy est ailleurs :

```bash
docker run --read-only --cap-drop=ALL --security-opt no-new-privileges \
  -p 127.0.0.1:8765:8765 \
  -e F5XC_TENANT=acme-corp -e F5XC_ALLOWED_NAMESPACES=prod \
  -e F5XC_MCP_BIND_HOST=0.0.0.0 -e F5XC_MCP_ALLOW_NON_LOOPBACK_BIND=true \
  -e F5XC_MCP_ALLOWED_HOSTS=mcp.example.com \
  f5xc-waap-mcp
```

### Journal d'audit et Splunk

Événements `tool_call`, `plan_created`, `plan_confirmation` et `plan_applied`, reliés
par `plan_id` et `request_id`, avec l'utilisateur XC nominatif. Pour Splunk :

- sur un hôte, `F5XC_MCP_AUDIT_LOG=/var/log/f5xc-waap-mcp/audit.jsonl` et un Universal
  Forwarder (`[monitor:///var/log/f5xc-waap-mcp/audit.jsonl]`, `sourcetype = _json`).
  Le fichier est créé en `0600` et rouvert après une rotation logrotate ;
- en conteneur, garder stderr et utiliser le logging driver `splunk` (ou le collecteur
  de logs du cluster).

## Dépendances et chaîne d'approvisionnement

- **Verrous :** `requirements*.lock` épinglent chaque paquet, transitifs compris, avec
  leurs hashes. Ils sont régénérés par `scripts/lock.sh` avec un délai de 14 jours sur
  les nouvelles versions ; les exceptions de sécurité sont listées dans le script.
- **CI :** actions épinglées par SHA, installations `--require-hashes`, ruff, bandit,
  pip-audit sur les trois verrous (et une fois par semaine), SBOM CycloneDX en
  artefact, construction et test de l'image (non-root, système de fichiers en lecture
  seule).

## Mettre à jour le catalogue

```bash
python scripts/generate_catalog.py
```

Le script échoue si un chemin utilisé n'existe plus dans la documentation.

## Seules les variables `F5XC_*` comptent

Le serveur ne lit que les variables préfixées `F5XC_` (et `F5XC_MCP_`). Des variables
génériques comme `MODE`, `API_TOKEN` ou `HTTPS_PROXY` n'ont aucun effet ; un test et une
règle Semgrep l'imposent (audit F-15).

## Preuves de sécurité

Réponse à l'audit, preuves et commandes de rejeu : [docs/AUDIT_RESPONSE.md](docs/AUDIT_RESPONSE.md).

| Outil | Ce qu'il prouve |
|---|---|
| Propriétés Hypothesis (`tests/test_diff_reconstruction.py`, `tests/test_audit_properties.py`) | Le diff se rejoue exactement ; aucune ligne forgeable ; aucun caractère invisible ne passe |
| `scripts/mutate_guards.py` | Chaque garde-fou retiré fait échouer au moins un test |
| `fuzz/fuzz_parsers.py` (atheris) | Requêtes de logs, chemins, sanitisation et diff tiennent leurs invariants sur entrées arbitraires |
| `.semgrep/rules.yml` | Pas de fuite de token vers log/erreur/réponse ; pas de chemin XC hors catalogue ; `fullmatch` imposé |
| `scripts/openapi_facts.py` | Faits tirés de la spec OpenAPI brute (pas de précondition de version, champs d'exclusion WAF, `whoami`) |

## Licence

MIT, voir [LICENSE](LICENSE). Le fichier embarqué
`src/f5xc_waap_mcp/data/public_suffix_list.dat` est la [Public Suffix List](https://publicsuffix.org),
sous licence MPL-2.0 (en-tête conservé), rafraîchie par `scripts/update_psl.py`.
