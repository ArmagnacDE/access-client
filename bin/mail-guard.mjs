#!/usr/bin/env node
// mail-guard: Mail-Wächter (S114), nur lesend, Meldung per ntfy. Aufruf und Exit-Codes: src/mail-guard-cli.js
import { run } from '../src/mail-guard-cli.js';

process.exitCode = await run(process.argv.slice(2));
