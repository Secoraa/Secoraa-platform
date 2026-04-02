from __future__ import annotations

from typing import List

COMMON_WORDS = [
    # ── Web / App tier ────────────────────────────────────────────────────
    "www", "www1", "www2", "www3", "www4", "web", "web1", "web2", "web3",
    "app", "app1", "app2", "app3", "webapp", "frontend", "backend",
    "static", "assets", "cdn", "cdn2", "media", "images", "img",
    "js", "css", "fonts", "download", "downloads", "upload", "uploads",
    "files", "docs", "help", "support", "status", "health", "landing",
    "home", "site", "www-dev", "www-staging",

    # ── API / Services ────────────────────────────────────────────────────
    "api", "api2", "api3", "api-v2", "api-v3", "graphql", "rest", "rpc",
    "gateway", "oauth", "auth", "sso", "login", "accounts", "id",
    "identity", "connect", "webhook", "webhooks", "callback", "ws",
    "wss", "socket", "realtime", "push", "notify", "events",
    "service", "services", "microservice",

    # ── Email / Comms ─────────────────────────────────────────────────────
    "mail", "mail1", "mail2", "mail3", "smtp", "imap", "pop", "pop3",
    "mx", "mx1", "mx2", "email", "webmail", "exchange", "autodiscover",
    "chat", "im", "slack", "teams", "meet", "conference", "voip", "sip",
    "mta", "postfix",

    # ── Infrastructure ────────────────────────────────────────────────────
    "ns", "ns1", "ns2", "ns3", "ns4", "dns", "dns1", "dns2",
    "vpn", "vpn1", "vpn2", "remote", "proxy", "reverse",
    "lb", "lb1", "lb2", "load", "balancer", "edge",
    "cache", "redis", "memcached", "queue", "mq", "rabbitmq", "kafka",
    "ntp", "time", "ftp", "sftp", "ssh", "bastion", "jump",
    "relay", "router", "firewall", "waf",
    "backup", "bak", "archive", "storage",
    "srv", "srv1", "srv2", "srv3",
    "server", "server1", "server2", "server3",
    "host", "host1", "host2", "host3",
    "node", "node1", "node2", "node3",

    # ── DevOps / CI-CD ────────────────────────────────────────────────────
    "jenkins", "ci", "cd", "build", "deploy", "release",
    "gitlab", "github", "bitbucket", "drone", "argo", "argocd",
    "ansible", "puppet", "chef", "terraform",
    "vault", "consul", "nomad",
    "docker", "registry", "harbor",
    "k8s", "kubernetes", "kube", "cluster", "worker", "master", "etcd",
    "istio", "envoy", "traefik", "nginx", "apache", "caddy", "haproxy",
    "prometheus", "grafana", "kibana",
    "elastic", "elasticsearch", "logstash", "fluentd",
    "loki", "tempo", "jaeger", "zipkin", "sentry",
    "sonar", "sonarqube", "artifactory", "nexus",

    # ── Environments ──────────────────────────────────────────────────────
    "dev", "dev1", "dev2", "development",
    "test", "test1", "test2", "testing",
    "qa", "qa1", "qa2", "uat",
    "staging", "stage", "stg",
    "preprod", "pre", "pre-prod",
    "prod", "production", "live",
    "demo", "sandbox", "canary", "preview", "nightly",

    # ── Admin / Internal ──────────────────────────────────────────────────
    "admin", "admin2", "administrator", "panel",
    "dashboard", "console", "manage", "management", "manager",
    "cms", "cpanel", "whm", "plesk", "webmin",
    "phpmyadmin", "pma", "adminer",
    "internal", "intranet", "corp", "corporate",
    "office", "staff", "hr", "finance", "legal",
    "ops", "operations", "infra", "it", "security",
    "backoffice", "extranet",

    # ── Database ──────────────────────────────────────────────────────────
    "db", "db1", "db2", "db3", "database",
    "mysql", "postgres", "postgresql",
    "mongo", "mongodb", "mariadb",
    "sql", "mssql", "oracle",
    "cassandra", "couchdb",
    "influx", "influxdb", "clickhouse",

    # ── Cloud / SaaS ─────────────────────────────────────────────────────
    "aws", "s3", "ec2", "lambda",
    "azure", "gcp", "cloud", "cloud2",
    "heroku", "netlify", "vercel", "render",
    "compute", "function", "serverless",
    "origin", "origin2",

    # ── Content / Business ────────────────────────────────────────────────
    "blog", "news", "press", "community", "forum",
    "wiki", "kb", "knowledge",
    "learn", "academy", "training", "edu", "education",
    "shop", "store", "ecommerce", "commerce",
    "pay", "payment", "payments", "billing", "invoice",
    "checkout", "cart", "order", "orders",
    "crm", "erp", "jira", "confluence",

    # ── Monitoring / Security ─────────────────────────────────────────────
    "monitor", "monitoring", "nagios", "zabbix",
    "datadog", "newrelic", "apm",
    "log", "logs", "logging", "audit",
    "scan", "scanner", "alert", "alerts",
    "pager", "oncall", "incident",
    "nessus", "qualys", "splunk", "siem",

    # ── Misc common ───────────────────────────────────────────────────────
    "portal", "beta", "alpha", "v2", "v3",
    "new", "old", "legacy",
    "m", "mobile", "android", "ios",
    "go", "link", "links", "redirect", "short", "url",
    "track", "tracking", "analytics", "stats", "metrics",
    "pixel", "tag", "gtm",
    "ads", "adserver", "marketing", "promo", "campaign",
    "affiliate", "partner", "reseller",
    "client", "clients", "customer", "customers",
    "user", "users", "member", "members",
    "signup", "register", "onboard", "welcome",
    "feedback", "survey", "report", "reports",
    "search", "data", "info", "about", "contact",
    "careers", "jobs", "apply",
    "lyncdiscover", "enterpriseregistration",
    "msoid", "selector1", "selector2",
]


def bruteforce_subdomains(domain: str) -> List[str]:
    """
    Generate possible subdomains using wordlist.
    """
    return [f"{word}.{domain}" for word in COMMON_WORDS]
