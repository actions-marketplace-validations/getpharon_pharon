// Service mapping table (spec §5.5): package names, env var names and config files -> third-party service.
// Ships with the CLI; the server serves it signed at /v1/service-map and the CLI swaps in a newer verified copy.
// Bump SERVICE_MAP_VERSION whenever SERVICES changes.
export const SERVICE_MAP_VERSION = 2;

const S = (vendor, npm = [], pypi = [], env = [], files = [], other = {}) => ({ vendor, npm, pypi, env, files, other });

// npm/pypi entries ending in "*" are prefixes. env entries are name prefixes (or exact names).
export const SERVICES = [
  S("stripe", ["stripe", "@stripe/*"], ["stripe"], ["STRIPE_"], [], { go: ["github.com/stripe/stripe-go*"], rubygems: ["stripe"], packagist: ["stripe/stripe-php"], maven: ["com.stripe:stripe-java"], nuget: ["stripe.net"] }),
  S("supabase", ["@supabase/*"], ["supabase"], ["SUPABASE_"]),
  S("litellm", [], ["litellm"], ["LITELLM_"]),
  S("openai", ["openai", "@ai-sdk/openai"], ["openai"], ["OPENAI_"], [], { go: ["github.com/openai/openai-go*", "github.com/sashabaranov/go-openai"], rubygems: ["ruby-openai", "openai"], packagist: ["openai-php/*"], maven: ["com.openai:*"], nuget: ["openai"] }),
  S("anthropic", ["@anthropic-ai/*", "@ai-sdk/anthropic"], ["anthropic"], ["ANTHROPIC_"], [], { go: ["github.com/anthropics/anthropic-sdk-go*"], rubygems: ["anthropic"], maven: ["com.anthropic:*"], nuget: ["anthropic*"] }),
  S("google-ai", ["@google/generative-ai", "@google/genai", "@ai-sdk/google"], ["google-generativeai", "google-genai"], ["GEMINI_", "GOOGLE_API_KEY"]),
  S("mistral", ["@mistralai/*"], ["mistralai"], ["MISTRAL_"]),
  S("cohere", ["cohere-ai"], ["cohere"], ["COHERE_"]),
  S("groq", ["groq-sdk"], ["groq"], ["GROQ_"]),
  S("huggingface", ["@huggingface/*"], ["huggingface-hub", "huggingface_hub"], ["HF_TOKEN", "HUGGINGFACE_"]),
  S("replicate", ["replicate"], ["replicate"], ["REPLICATE_"]),
  S("pinecone", ["@pinecone-database/*"], ["pinecone", "pinecone-client"], ["PINECONE_"]),
  S("aws", ["@aws-sdk/*", "aws-sdk"], ["boto3", "botocore", "aiobotocore"], ["AWS_"], [], { go: ["github.com/aws/aws-sdk-go*"], rubygems: ["aws-sdk*"], packagist: ["aws/aws-sdk-php"], maven: ["software.amazon.awssdk:*", "com.amazonaws:*"], nuget: ["awssdk.*"], cargo: ["aws-sdk-*", "aws-config"] }),
  S("google-cloud", ["@google-cloud/*"], ["google-cloud-*"], ["GOOGLE_APPLICATION_CREDENTIALS", "GCP_", "GCLOUD_"]),
  S("azure", ["@azure/*"], ["azure-*"], ["AZURE_"]),
  S("firebase", ["firebase", "firebase-admin"], ["firebase-admin"], ["FIREBASE_"]),
  S("cloudflare", ["cloudflare", "wrangler", "@cloudflare/*"], ["cloudflare"], ["CLOUDFLARE_", "CF_API_"], ["wrangler.toml", "wrangler.json", "wrangler.jsonc"]),
  S("vercel", ["@vercel/*", "vercel"], [], ["VERCEL_"], ["vercel.json"]),
  S("netlify", ["@netlify/*", "netlify-cli"], [], ["NETLIFY_"], ["netlify.toml"]),
  S("fly", [], [], ["FLY_API_TOKEN"], ["fly.toml"]),
  S("railway", [], [], ["RAILWAY_"], ["railway.json", "railway.toml"]),
  S("render", [], [], ["RENDER_"], ["render.yaml"]),
  S("sendgrid", ["@sendgrid/*"], ["sendgrid"], ["SENDGRID_"]),
  S("twilio", ["twilio"], ["twilio"], ["TWILIO_"]),
  S("resend", ["resend"], ["resend"], ["RESEND_"]),
  S("postmark", ["postmark"], ["postmarker"], ["POSTMARK_"]),
  S("mailgun", ["mailgun.js", "mailgun-js"], [], ["MAILGUN_"]),
  S("mailchimp", ["@mailchimp/*"], ["mailchimp-marketing", "mailchimp3"], ["MAILCHIMP_"]),
  S("sentry", ["@sentry/*"], ["sentry-sdk"], ["SENTRY_"], [], { go: ["github.com/getsentry/sentry-go"], rubygems: ["sentry-ruby", "sentry-rails"], packagist: ["sentry/sentry*"], maven: ["io.sentry:*"], nuget: ["sentry*"], cargo: ["sentry"] }),
  S("datadog", ["dd-trace", "@datadog/*"], ["ddtrace", "datadog"], ["DATADOG_", "DD_API_KEY"]),
  S("posthog", ["posthog-js", "posthog-node"], ["posthog"], ["POSTHOG_", "NEXT_PUBLIC_POSTHOG_"]),
  S("segment", ["@segment/*", "analytics-node"], ["segment-analytics-python", "analytics-python"], ["SEGMENT_"]),
  S("mixpanel", ["mixpanel", "mixpanel-browser"], ["mixpanel"], ["MIXPANEL_"]),
  S("auth0", ["auth0", "@auth0/*"], ["auth0-python"], ["AUTH0_"]),
  S("clerk", ["@clerk/*"], ["clerk-backend-api"], ["CLERK_", "NEXT_PUBLIC_CLERK_"]),
  S("github", ["@octokit/*", "octokit"], ["pygithub", "githubkit"], ["GITHUB_TOKEN", "GH_TOKEN"]),
  S("slack", ["@slack/*"], ["slack-sdk", "slack-bolt"], ["SLACK_"]),
  S("algolia", ["algoliasearch", "@algolia/*"], ["algoliasearch"], ["ALGOLIA_"]),
  S("upstash", ["@upstash/*"], ["upstash-redis"], ["UPSTASH_"]),
  S("neon", ["@neondatabase/*"], [], ["NEON_"]),
  S("planetscale", ["@planetscale/*"], [], ["PLANETSCALE_"]),
  S("mongodb", ["mongodb", "mongoose"], ["pymongo", "motor"], ["MONGODB_", "MONGO_URL", "MONGO_URI"], [], { go: ["go.mongodb.org/mongo-driver*"], rubygems: ["mongo", "mongoid"], packagist: ["mongodb/mongodb"], maven: ["org.mongodb:*"], nuget: ["mongodb.driver"], cargo: ["mongodb"] }),
  S("redis", ["redis", "ioredis", "@redis/*"], ["redis"], ["REDIS_"], [], { go: ["github.com/redis/go-redis*", "github.com/go-redis/redis*"], rubygems: ["redis"], packagist: ["predis/predis"], maven: ["redis.clients:jedis", "io.lettuce:lettuce-core"], nuget: ["stackexchange.redis"], cargo: ["redis"] }),
  S("postgresql", ["pg", "postgres", "@neondatabase/serverless"], ["psycopg", "psycopg2", "psycopg2-binary", "asyncpg"], ["POSTGRES_", "PGHOST"], [], { go: ["github.com/jackc/pgx*", "github.com/lib/pq"], rubygems: ["pg"], maven: ["org.postgresql:postgresql"], nuget: ["npgsql"], cargo: ["tokio-postgres", "postgres", "sqlx"] }),
  S("mysql", ["mysql", "mysql2"], ["pymysql", "mysqlclient", "aiomysql"], ["MYSQL_"]),
  S("elasticsearch", ["@elastic/elasticsearch"], ["elasticsearch"], ["ELASTICSEARCH_", "ELASTIC_"]),
  S("kafka", ["kafkajs", "@confluentinc/*"], ["confluent-kafka", "kafka-python", "aiokafka"], ["KAFKA_"]),
  S("rabbitmq", ["amqplib"], ["pika", "aio-pika"], ["RABBITMQ_", "AMQP_URL"]),
  S("plaid", ["plaid"], ["plaid-python"], ["PLAID_"]),
  S("paypal", ["@paypal/*"], ["paypalrestsdk"], ["PAYPAL_"]),
  S("shopify", ["@shopify/*"], ["shopifyapi"], ["SHOPIFY_"]),
  S("launchdarkly", ["launchdarkly-node-server-sdk", "@launchdarkly/*"], ["launchdarkly-server-sdk"], ["LAUNCHDARKLY_"]),
  S("cloudinary", ["cloudinary"], ["cloudinary"], ["CLOUDINARY_"]),
  S("pusher", ["pusher", "pusher-js"], ["pusher"], ["PUSHER_"]),
];

let active = SERVICES;
/** Use a newer table (already signature-verified by the caller). */
export function setServiceMap(services) {
  active = services;
}

const hit = (list, name) => list.some((p) => (p.endsWith("*") ? name.startsWith(p.slice(0, -1)) : name === p));

export function serviceForPackage(ecosystem, name) {
  const n = name.toLowerCase();
  return active.find((s) => hit(ecosystem === "npm" ? s.npm : ecosystem === "pypi" ? s.pypi : (s.other?.[ecosystem] ?? []), n))?.vendor ?? null;
}

export function serviceForEnv(varName) {
  return active.find((s) => s.env.some((p) => (p.endsWith("_") ? varName.startsWith(p) : varName === p)))?.vendor ?? null;
}

export function serviceForFile(basename) {
  return active.find((s) => s.files.includes(basename))?.vendor ?? null;
}

const VENDOR_NAMES = { aws: "AWS", postgresql: "PostgreSQL", redis: "Redis", mysql: "MySQL", mongodb: "MongoDB", elasticsearch: "Elasticsearch", kafka: "Kafka", rabbitmq: "RabbitMQ", "google-cloud": "Google Cloud", azure: "Azure", database: "Database" };
export const vendorName = (v) => VENDOR_NAMES[v] ?? v;

/** Plain-language gap descriptions, shared by the CLI and the web app. */
export function gapText(g) {
  const name = vendorName(g.provider);
  return (
    {
      aws_used_no_iac: "AWS is used, but no infrastructure-as-code describes the resources",
      server_version_unknown: `${name} is used, but the server version is unknown`,
      database_provider_unknown: "DATABASE_URL is used, but the database provider is unknown",
      provider_used_no_scanner: `${name} is used; its resources aren't tracked yet`,
      permission_denied: `${name}: some resources couldn't be read (permission denied)`,
      version_from_variable: `${name} ${g.service ?? ""}: the version comes from a Terraform variable, so it's unknown`.replace("  ", " "),
      scan_error: `${name}: part of the cloud scan failed`,
      scan_stale: `${name}: the last cloud scan is over a week old (scans run from the machine of whoever chose the AWS CLI)`,
    }[g.reason] ?? `${name}: ${String(g.reason).replaceAll("_", " ")}`
  );
}
