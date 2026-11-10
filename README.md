# Status

Private Statusseite. Die Daten liegen nur verschlüsselt im Repo (`*.enc.json`, AES-GCM,
Schlüssel per PBKDF2-SHA256 aus einem Zugangscode, Parameter in `kdf.json`).
Ohne Code zeigt die Seite nur ein Eingabefeld.
