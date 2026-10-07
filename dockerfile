FROM node:18-alpine

# No configuration in the image. This file used to take SDK_BACKEND_SECRET and
# MEETING_PLATFORM_JWT_SECRET as build args and set them as ENV, so
# `docker inspect` on the image printed them. The environment arrives at RUN
# time instead — server.js reads it through dotenv or the process env:
#   docker run --env-file /etc/samvyo/demo-server.env -p 5100:5100 <image>
# with SERVER_URL, SDK_BACKEND_SECRET, MEETING_PLATFORM_JWT_SECRET, PORT, and
# CERT_DIR (mount it) for HTTPS, or none for HTTP behind a TLS proxy.
# .dockerignore keeps every .env* file out of the build context.
ENV NODE_ENV=production

WORKDIR /app

COPY package*.json ./

RUN npm install --legacy-peer-deps

COPY . .

EXPOSE 5100

CMD ["npm", "run", "start"]
