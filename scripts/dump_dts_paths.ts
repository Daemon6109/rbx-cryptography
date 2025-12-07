// Dumps exported paths from types/index.d.ts into api-dts.txt
// Usage: npx ts-node scripts/dump_dts_paths.ts (or node after ts-node/register)
import fs from "fs";
import path from "path";
import url from "url";

const __filename = url.fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dtsPath = path.resolve(__dirname, "../types/index.d.ts");
const outPath = path.resolve(__dirname, "../api-dts.txt");
const src = fs.readFileSync(dtsPath, "utf8");

const paths = new Set<string>();
const nsStack: string[] = [];

for (const raw of src.split(/\r?\n/)) {
	const line = raw.trim();
	const nsOpen = line.match(/^namespace\s+(\w+)/);
	if (nsOpen) {
		nsStack.push(nsOpen[1]);
		continue;
	}
	if (line === "}" && nsStack.length > 0) {
		nsStack.pop();
		continue;
	}

	const func = line.match(/^function\s+(\w+)/);
	const konst = line.match(/^const\s+(\w+)/);
	const lett = line.match(/^let\s+(\w+)/);
	if (func || konst || lett) {
		const name = (func || konst || lett)![1];
		const pathStr = ["Cryptography", ...nsStack, name].join(".") + (func ? "()" : "");
		paths.add(pathStr);
	}
}

const sorted = [...paths].sort();
fs.writeFileSync(outPath, sorted.join("\n"));
console.log(`Wrote ${sorted.length} entries to ${outPath}`);
