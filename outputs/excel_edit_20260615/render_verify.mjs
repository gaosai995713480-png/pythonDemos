import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";
const input = await FileBlob.load(process.argv[2]);
const renderPath = process.argv[3];
const workbook = await SpreadsheetFile.importXlsx(input);
const blob = await workbook.render({ sheetName: '业财', range: 'A1:F8', scale: 2 });
await blob.save(renderPath);
console.log(renderPath);
