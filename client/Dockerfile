FROM nginx:1.27-alpine

# Healthcheck endpoint
RUN echo "ok" > /usr/share/nginx/html/healthz

# Static SPA assets are bind-mounted at runtime for dev;
# for a prod image, COPY src/ /usr/share/nginx/html/ here.
COPY src/ /usr/share/nginx/html/

EXPOSE 3000
