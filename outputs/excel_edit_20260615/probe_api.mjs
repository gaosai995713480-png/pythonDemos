import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const inputPath = process.argv[2];
const input = await FileBlob.load(inputPath);
const workbook = await SpreadsheetFile.importXlsx(input);
const sheet = workbook.worksheets.getItem("业财");
const used = sheet.getUsedRange();
console.log(JSON.stringify({ rows: used.rowCount, cols: used.columnCount, sample: used.getCell(0,0).value }));
