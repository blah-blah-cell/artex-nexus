import packageJson from "../../package.json";

import { t } from "@/i18n";

const currentYear = new Date().getFullYear();

export const APP_CONFIG = {
  name: "ARTEX-Nexus",
  version: `${packageJson.version}+nexus.0.5.0`,
  copyright: `© ${currentYear}, ARTEX-Nexus (powered by BaaRai/ARTEX).`,
  meta: {
    title: t("ARTEX-Nexus — Autonomous Security & CVE Intelligence Console"),
    description: t("Unified autonomous security operations, offline Medium+ CVE intelligence, and hash-chained verification console"),
  },
};
