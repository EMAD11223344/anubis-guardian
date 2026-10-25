# honeypot seed: DOCKER-001 root + DOCKER-002 :latest + DOCKER-003 ARG secret
FROM node:latest
ARG DATABASE_PASSWORD
ENV DB_PASS=$DATABASE_PASSWORD
COPY . .
RUN npm ci --production
CMD ["npm", "start"]
