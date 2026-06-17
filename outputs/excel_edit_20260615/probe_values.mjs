import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";
const input = await FileBlob.load(process.argv[2]);
const workbook = await SpreadsheetFile.importXlsx(input);
const sheet = workbook.worksheets.getItem('业财');
const used = sheet.getUsedRange();
const range = sheet.getRange(`A1:F${used.rowCount}`);
const result = {
  usedRows: used.rowCount,
  usedCols: used.columnCount,
  hasRangeValues: Array.isArray(range.values),
  firstTwoRows: Array.isArray(range.values) ? range.values.slice(0, 2) : null,
  hasUsedValues: Array.isArray(used.values),
  firstTwoUsedRows: Array.isArray(used.values) ? used.values.slice(0, 2) : null,
};
console.log(JSON.stringify(result, null, 2));
