import { FileBlob, SpreadsheetFile } from "@oai/artifact-tool";

function toNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  if (typeof value === 'number') return value;
  if (typeof value === 'string') {
    const trimmed = value.trim();
    if (!trimmed) return null;
    const parsed = Number(trimmed);
    return Number.isFinite(parsed) ? parsed : null;
  }
  return null;
}

function colToLetter(colIndex1Based) {
  let n = colIndex1Based;
  let result = '';
  while (n > 0) {
    const rem = (n - 1) % 26;
    result = String.fromCharCode(65 + rem) + result;
    n = Math.floor((n - 1) / 26);
  }
  return result;
}

const [inputPath, outputPath] = process.argv.slice(2);
const input = await FileBlob.load(inputPath);
const workbook = await SpreadsheetFile.importXlsx(input);
const sheet = workbook.worksheets.getItem('业财');
const used = sheet.getUsedRange();
const values = used.values.map(row => [...row]);

const headers = values[0] ?? [];
const minCol = headers.indexOf('最小时间_S');
const maxCol = headers.indexOf('最大时间_ms');
if (minCol < 0 || maxCol < 0) {
  throw new Error(`未找到目标列: minCol=${minCol}, maxCol=${maxCol}, headers=${JSON.stringify(headers)}`);
}

let minUpdated = 0;
let maxUpdated = 0;
const samples = [];
for (let r = 1; r < values.length; r += 1) {
  const row = values[r];
  const path = row[1];

  const oldMin = toNumber(row[minCol]);
  if (oldMin !== null) {
    const newMin = oldMin * 1000;
    row[minCol] = newMin;
    minUpdated += 1;
    if (samples.length < 3) {
      samples.push({ row: r + 1, path, oldMin, newMin });
    }
  }

  const oldMax = toNumber(row[maxCol]);
  if (oldMax !== null) {
    const newMax = Number((oldMax * 1000).toFixed(4));
    row[maxCol] = newMax;
    maxUpdated += 1;
  }
}

used.values = values;

if (values.length > 1) {
  const maxColLetter = colToLetter(maxCol + 1);
  sheet.getRange(`${maxColLetter}2:${maxColLetter}${values.length}`).format.numberFormat = '0.0000';
}

const output = await SpreadsheetFile.exportXlsx(workbook);
await output.save(outputPath);

console.log(JSON.stringify({
  rowCount: values.length,
  minUpdated,
  maxUpdated,
  minColumn: minCol + 1,
  maxColumn: maxCol + 1,
  samples,
}, null, 2));
