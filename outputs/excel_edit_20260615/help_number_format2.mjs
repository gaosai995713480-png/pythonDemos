import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";
const input = await FileBlob.load(process.argv[2]);
const workbook = await SpreadsheetFile.importXlsx(input);
const help = workbook.help("numberFormat", { include: "index,examples,notes", maxChars: 3000 });
console.log(help.ndjson);
