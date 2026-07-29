# URL Trust Analyzer

Un prototype d'analyse d'URL composé d'un backend FastAPI et d'un frontend React/Vite.

## Structure

- `backend/` : API Python FastAPI
- `frontend/` : interface React + TypeScript
- `docker-compose.yml` : orchestration des services

## Installation Backend

```bash
cd backend
python -m pip install -r requirements.txt
```

## Lancer le backend

```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Le backend écoute sur : http://127.0.0.1:8000

## Installation Frontend

```bash
cd frontend
npm install
```

## Lancer le frontend

```bash
cd frontend
npm run dev -- --host 127.0.0.1 --port 5173
```

Le frontend écoute sur : http://127.0.0.1:5173 et proxifie les requêtes `/api` vers le backend.

## Démarrage rapide local

Sur Windows, vous pouvez démarrer les deux services d’un seul coup :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1
```

Pour arrêter les processus de développement :

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop.ps1
```

Le tableau de bord affiche maintenant l’historique des analyses effectuées.

## Exécution avec Docker Compose

```bash
docker compose up --build
```

- backend : http://127.0.0.1:8000
- frontend : http://127.0.0.1:5173

Le frontend est déjà configuré pour proxyfier `/api` vers le backend.

## Endpoint d'analyse

- `POST /analyze` : analyse une URL via plusieurs sources (RDAP, URL statique, DNS, et signaux de réputation)
- `GET /history` : récupère les dernières analyses stockées en base

## Authentification

L'application utilise une authentification par cookie sécurisé HTTP-only.
Les mots de passe sont stockés uniquement sous forme de hash sécurisé, sans conserver de données sensibles.

- `POST /auth/register` : créer un compte utilisateur
- `POST /auth/login` : se connecter
- `POST /auth/logout` : se déconnecter
- `GET /auth/me` : récupérer l'utilisateur connecté

Exemple :

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Branche

Le travail principal est sur la branche `v0.1`.
