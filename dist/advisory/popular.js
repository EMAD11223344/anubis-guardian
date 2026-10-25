/** Popular npm packages (offline seed list for typosquat distance + unknown-package triage). */
export const POPULAR = new Set(`react react-dom next vue svelte angular express nestjs @nestjs/core @nestjs/common @nestjs/platform-express
fastify koa hapi hono @supabase/supabase-js @supabase/ssr supabase-js prisma @prisma/client sequelize typeorm mongoose
knex drizzle-orm drizzle-kit redis ioredis mongodb mysql2 pg sqlite3 lodash ramda axios undici node-fetch got ky superagent
jsonwebtoken jose passport passport-jwt passport-local bcrypt bcryptjs argon2 jsonwebtoken oidc-client-ts
zod yup joi class-validator class-transformer io-ts ajv
jest vitest mocha ava playwright puppeteer cypress @playwright/test
typescript ts-node tsx esbuild swc @babel/core @babel/preset-env webpack vite rollup parcel turbo
eslint prettier biome stylelint standard
socket.io socket.io-client ws engine.io mqtt
tailwindcss @tailwindcss/typography sass less postcss styled-components @emotion/react framer-motion
three babylonjs pixi.js phaser d3 chart.js recharts victory react-hook-form formik @tanstack/react-query @tanstack/react-table
zustand jotai redux @reduxjs/toolkit mobx recoil xstate
next-auth clerk @clerk/nextjs firebase firebase-admin aws-sdk @aws-sdk/client-s3 stripe @stripe/stripe-js
openai @anthropic-ai/sdk langchain cohere-ai replicate @google/generative-ai
dotenv cross-env rimraf concurrently nodemon pm2 forever dotenv-expand
glob minimatch chokidar fs-extra del rimraf shelljs execa cross-spawn which os tmp uuid nanoid shortid
moment dayjs date-fns luxon slugify marked markdown-it showdown handlebars ejs pug mustache nunjucks
cheerio jsdom dompurify sanitize-html xss diff
commander yargs meow inquirer prompts enquirer cac clipanion oclif
chalk picocolors kleur colors ora nanospinner cli-progress boxen figures log-update ink
winston pino debug loglevel bunyan morgan winston-daily-rotate-file
multer busboy formidable multipart sharp jimp gm image-size
archiver adm-zip unzipper yauzl yazl tar compressing
jsonwebtoken googleapis google-auth-library @google-cloud/storage @azure/storage-blob
swagger-ui-express @nestjs/swagger swagger-jsdoc openapi-types redoc
amqplib kafkajs bull bullmq bee-queue agenda nats
graphql apollo-server @apollo/server graphql-request graphql-tag urql relay-runtime
@testing-library/react @testing-library/jest-dom @vue/test-utils enzyme
i18next react-i18next vue-i18next intl formatjs
helmet cors body-parser cookie-parser compression morgan serve-static
newrelic sentry @sentry/node @sentry/react bugsnag datadog pino-http
node-cron node-schedule agenda bree later
csv-parse csv-stringify papaparse xlsx exceljs sheetjs
canvas fabric konva p5 gsap animejs lottie-web @lottiefiles/react-lottie-player
clean-deep deepmerge merge-deep lodash.merge object-assign deep-copy clone extend defaults
is-odd is-even is-number kind-of classnames clsx tailwind-merge
dotenv-vault googletrends duplicate-package-checker-webpack-plugin
webpack-dev-server vite-plugin-react @vitejs/plugin-react @vitejs/plugin-vue
preact solid-js qwiklit qwik astro svelte-kit @sveltejs/kit nuxt @nuxtjs/kit nitropack
expo react-native @react-navigation/native @expo/cli
electron tauri @tauri-apps/cli neutrino
nodemailer sendgrid @sendgrid/mail mailgun-js resend postmark nodemailer-sendgrid
twilio Vonage messagebird pusher ably firebase-functions
rate-limiter-flexible express-rate-limit slowdown express-brute
jsonwebtoken cache-manager lru-cache node-cache memory-cache apollo-server-caching
mjml juice html-to-text string-strip-html
p-limit p-queue p-map async bluebird q when
ramda immer immerhx htm nanoid-parser
yaml js-yaml toml ini xml2js fast-xml-parser plist
ua-parser-js platform mobile-detect booted
zoomus zoom-sdk peerjs simple-peer webrtc-adapter mediasoup
crc crc32 hash-wasm node-forge forge jsencrypt crypto-js
validator email-validator isemail phone google-libphonenumber libphonenumber-js
google-maps @googlemaps/js-api-loader leaflet mapbox-gl @react-google-maps/api
swiper slick-carousel aos wow.js scrollreveal typed.js particles.js
mqtt.js paho-mqtt sockette pusher-js
multer-s3 @aws-sdk/lib-storage minio
sharp-cli imageoptim imagemin jimp
fast-json-stringify fastify-plugin @fastify/cors @fastify/helmet
http-proxy http-proxy-middleware cors-anywhere node-fetch-proxy
pino-pretty debug-http axios-logger
json5 jsonc-parser hjson json-parse-better-errors
change-case pluralize inflection title-case
normalize.css reset-css modern-normalize bourbon
react-icons @heroicons/react lucide-react @mui/material @mui/icons-material antd @chakra-ui/react mantine @radix-ui/react
daisyui flowbite headlessui @headlessui/react @headlessui/vue
dayjs-plugin-utc datezone datepicker flatpickr pikaday bootstrap jquery
sass-loader css-loader style-loader mini-css-extract-plugin postcss-loader
terser uglify-js babel-minify clean-webpack-plugin compression-webpack-plugin
workbox PrecacheController @sentry/vite-plugin
husky lint-staged commitizen semantic-release standard-version changesets @changesets/cli
np release-it punchcard
vitest-preview canvas-confetti
@vercel/node @vercel/react
supertest chai sinon should assert babylon
node-notifier open opn react-toastify notie sweetalert2 toastr
split2 pump through2 mississippi streamx readable-stream
level lowdb nedb pouchdb rxdb seqlite better-sqlite3 duckdb @libsql/client
graphology vis-network cytoscape d3-force
paperjs matter-js cannon-es planck rapier2d
mjml-browser nodemailer-express-handlebars
paypal-checkout @paypal/react-paypal-js braintree web3 ethers hardhat @openzeppelin/contracts
algoliasearch meilisearch typesense elastic @elastic/elasticsearch lunr fuse.js flexsearch minisearch
qrcode qr-code-styling jsbarcode
exceljs4 papaparse5 xlsx-populate
compare-versions semver-compare semver-diff node-semver
kill-port wait-on tree-kill terminate ps-list fkill
envinfo systeminformation os-name public-ip internal-ip
chance faker @faker-js/faker casual randexp uuidv4
minimist-options yargs-parser mri arg nopt
kleur piccolo colorette supports-color has-flag
retry async-retry got-retry backoff
bytes kb ms pretty-bytes humanize filesize
trash move-file make-dir tempy conf store2
`
    .split(/\s+/)
    .map((s) => s.trim())
    .filter(Boolean));
/** Damerau-Levenshtein distance (bounded) — offline typosquat heuristic. */
export function damerau(a, b, max = 3) {
    if (Math.abs(a.length - b.length) > max)
        return max + 1;
    const al = a.length, bl = b.length;
    const d = Array.from({ length: al + 1 }, () => new Array(bl + 1).fill(0));
    for (let i = 0; i <= al; i++)
        d[i][0] = i;
    for (let j = 0; j <= bl; j++)
        d[0][j] = j;
    for (let i = 1; i <= al; i++) {
        for (let j = 1; j <= bl; j++) {
            const cost = a[i - 1] === b[j - 1] ? 0 : 1;
            d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
            if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
                d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
            }
        }
    }
    return d[al][bl];
}
/** Nearest popular package within distance ≤ max (typosquat candidate). */
export function nearestPopular(name, max = 2) {
    let best = null;
    for (const p of POPULAR) {
        const dist = damerau(name, p, max);
        if (dist <= max && (!best || dist < best.distance))
            best = { target: p, distance: dist };
        if (best && best.distance === 1)
            break;
    }
    return best;
}
