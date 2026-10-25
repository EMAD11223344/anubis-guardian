# clean case: pinned base image, non-root user, no ARG secrets
FROM node:20.18-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY . .
USER node
CMD ["npm", "start"]
