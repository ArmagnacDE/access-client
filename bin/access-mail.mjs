#!/usr/bin/env node
// access-mail: Mail-Entwürfe in einem Postfach der Domain (nie senden). Hilfe: access-mail help
import { run } from '../src/mail/cli.js';

process.exitCode = await run(process.argv.slice(2));
