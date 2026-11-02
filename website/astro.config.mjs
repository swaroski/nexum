import { defineConfig } from "astro/config";
import starlight from "@astrojs/starlight";

export default defineConfig({
  site: "https://swaroski.github.io",
  base: "/nexum",
  integrations: [
    starlight({
      title: "Nexum",
      description:
        "The open, vendor-neutral trust and authorization fabric for AI agents.",
      social: [{ icon: "github", label: "GitHub", href: "https://github.com/swaroski/nexum" }],
      editLink: { baseUrl: "https://github.com/swaroski/nexum/edit/main/website/" },
      customCss: ["./src/styles.css"],
      sidebar: [
        { label: "Start here", items: ["start/quickstart", "start/cross-company-demo", "playground", "integrations"] },
        {
          label: "Concepts",
          items: ["concepts/how-it-works", "concepts/delegation", "concepts/trust", "concepts/policy", "concepts/approvals-audit"],
        },
        {
          label: "Guides",
          items: [
            "guides/evals", "guides/observability", "guides/console", "guides/discovery-risk",
            "guides/mcp", "guides/a2a", "guides/opa", "guides/python", "guides/deploy",
          ],
        },
        { label: "Reference", items: ["reference/cli", "reference/http-api", "reference/config", "reference/reason-codes"] },
        { label: "Security", items: ["security/overview", "security/threat-model", "security/architecture"] },
        { label: "Project", items: ["project/roadmap", "project/platform"] },
      ],
    }),
  ],
});
