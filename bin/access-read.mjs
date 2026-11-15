#!/usr/bin/env node
// access-read: nur lesender Zugang zu Gmail, Drive und Sheets. Hilfe: access-read help
import { run } from '../src/read/cli.js';

process.exitCode = await run(process.argv.slice(2));
