import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";
const input = await FileBlob.load(process.argv[2]);
const workbook = await SpreadsheetFile.importXlsx(input);
const preview = await workbook.inspect({
  kind: "table",
  range: "业财!A1:F6",
  include: "values,formulas",
  tableMaxRows: 6,
  tableMaxCols: 6,
});
console.log(preview.ndjson);
