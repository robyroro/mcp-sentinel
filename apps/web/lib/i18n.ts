export const copy = {
  en: {
    dashboard: "Security overview", servers: "Server registry", tools: "Tool capabilities", policies: "Policies",
    sessions: "Live sessions", approvals: "Approvals", findings: "Security findings", sandboxes: "Sandbox manager",
    risk: "Risk dashboard", reports: "Reports & evidence", settings: "Workspace settings", signOut: "Sign out",
    command: "Command palette", live: "Live enforcement", search: "Search Sentinel", locale: "Language",
  },
  ro: {
    dashboard: "Prezentare de securitate", servers: "Registru de servere", tools: "Capabilități instrumente", policies: "Politici",
    sessions: "Sesiuni active", approvals: "Aprobări", findings: "Constatări de securitate", sandboxes: "Manager sandbox",
    risk: "Panou de risc", reports: "Rapoarte și dovezi", settings: "Setări spațiu", signOut: "Deconectare",
    command: "Paletă de comenzi", live: "Aplicare activă", search: "Caută în Sentinel", locale: "Limbă",
  },
} as const;

export type Locale = keyof typeof copy;
