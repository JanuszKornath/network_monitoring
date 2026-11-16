# Hinweise für Claude

## Pull-Request-Workflow

- Review-Kommentare auf GitHub (auch von Bots wie gemini-code-assist) immer
  direkt auf GitHub beantworten: kurz erläutern, ob und wie der Hinweis
  umgesetzt wurde (mit Commit-Referenz), oder begründen, warum nicht.
- Erledigte Review-Threads anschließend als "resolved" markieren, damit im
  PR sichtbar ist, dass die Unterhaltung abgeschlossen ist.
- Issues in PR-Beschreibungen und Commit-Messages immer mit englischen
  Closing-Keywords verknüpfen (`Closes #30`, `Fixes #30`, `Resolves #30`).
  Deutsche Formen wie "Schließt #30" erkennt GitHub nicht – das Issue bleibt
  dann nach dem Merge offen. Der restliche Text darf deutsch bleiben.
