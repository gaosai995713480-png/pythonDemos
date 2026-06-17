import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

const inputPath = process.argv[2];
const input = await FileBlob.load(inputPath);
const workbook = await SpreadsheetFile.importXlsx(input);
const preview = await workbook.inspect({
  kind: "table",
  range: "业财!A1:AZ6",
  include: "values,formulas",
  tableMaxRows: 6,
  tableMaxCols: 52,
});
console.log(preview.ndjson);
