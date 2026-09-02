// The verifier itself has no Node dependency: it runs on WebCrypto in a
// browser, a phone runtime or Node alike. Only the conformance test reads
// fixture files from disk. These are the two functions it uses, declared here
// so the test typechecks without pulling in @types/node for a package whose
// runtime never touches Node.
declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
}

declare module "node:path" {
  export function resolve(...segments: string[]): string;
}

declare const __dirname: string;
