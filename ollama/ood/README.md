# Open OnDemand app wrapper for Ollama

This folder contains a minimal Batch Connect app wrapper that launches an Ollama-backed Open WebUI experience from an Apptainer image.

## What to customize

- form.yml:
  - cluster
  - image_path default
  - partition default
  - account default
  - ollama_data_dir default
  - webui_data_dir default
  - resource defaults
- submit.yml.erb:
  - scheduler native flags for your cluster
  - optional partition/account routing

## Runtime behavior

The launch script:

- Uses assigned Open OnDemand port via the template variable `port`.
- Uses a randomized, session-local Ollama backend port via `OLLAMA_BACKEND_PORT`.
- Binds model storage to `/var/lib/ollama`.
- Binds Open WebUI state to `/var/lib/open-webui`.
- Starts `ollama serve` inside the container, then runs Open WebUI against the local Ollama endpoint.
- Enables Open WebUI password login and disables open signup.
- Shows a per-session generated password in `view.html.erb` so the user can copy it into the login form.

```bash
apptainer run ... ollama.sif
```

## New template files

- `template/before.sh.erb`: generates session port, randomized backend port, and a session password.
- `view.html.erb`: renders launch button and shows the generated password.
