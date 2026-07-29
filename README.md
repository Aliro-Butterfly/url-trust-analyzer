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
uvicorn backend.app.main:app --reload
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
npm run dev
```

Le frontend écoute sur : http://127.0.0.1:5173 et proxifie les requêtes `/api` vers le backend.

## Exécution avec Docker Compose

```bash
docker compose up --build
```

- backend : http://127.0.0.1:8000
- frontend : http://127.0.0.1:5173

Le frontend est déjà configuré pour proxyfier `/api` vers le backend.

## Endpoint d'analyse

- `POST /analyze` : analyse une URL via plusieurs sources (RDAP, URL statique, DNS, et signaux de réputation)

Exemple :

```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://example.com"}'
```

## Branche

Le travail principal est sur la branche `v0.1`.
