import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";
const input = await FileBlob.load(process.argv[2]);
const workbook = await SpreadsheetFile.importXlsx(input);
const help = workbook.help("range.numberFormat", { include: "examples,notes", maxChars: 2500 });
console.log(help.ndjson);
