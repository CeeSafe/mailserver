# syntax=docker/dockerfile:1.7
#
# The admin UI: CosmoMailAdmin's Nuxt frontend, unchanged, as its own Nitro server. deploy/build-admin-ui.sh builds
# it with vite+ (`vp install && vp run build`) and passes only `.output` as this image's context. Its server side
# calls the mail server's admin API at NUXT_API_BASE (the admin listener, on the compose network only).

FROM node:22-bookworm-slim
WORKDIR /app
COPY .output ./.output
ENV NODE_ENV=production HOST=0.0.0.0 PORT=9183
EXPOSE 9183
USER node
CMD ["node", ".output/server/index.mjs"]
