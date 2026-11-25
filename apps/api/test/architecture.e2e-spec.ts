import * as fs from 'fs';
import * as path from 'path';

describe('DDD Architectural Boundary Invariants', () => {
  const domainDir = path.resolve(__dirname, '../src/modules');

  function getFilesRecursively(dir: string): string[] {
    let results: string[] = [];
    const list = fs.readdirSync(dir);
    list.forEach((file) => {
      const fullPath = path.resolve(dir, file);
      const stat = fs.statSync(fullPath);
      if (stat && stat.isDirectory()) {
        results = results.concat(getFilesRecursively(fullPath));
      } else if (file.endsWith('.ts') && !file.endsWith('.spec.ts')) {
        results.push(fullPath);
      }
    });
    return results;
  }

  it('domain layers must have ZERO imports from @prisma/client, @nestjs/*, express, bullmq, or ioredis', () => {
    const allFiles = getFilesRecursively(domainDir);
    const domainFiles = allFiles.filter((f) => f.includes(`${path.sep}domain${path.sep}`));

    expect(domainFiles.length).toBeGreaterThan(0);

    const forbiddenImports = ['@prisma/client', '@nestjs', 'express', 'bullmq', 'ioredis'];
    const violations: { file: string; line: string }[] = [];

    domainFiles.forEach((filePath) => {
      const content = fs.readFileSync(filePath, 'utf-8');
      const lines = content.split('\n');

      lines.forEach((line) => {
        const trimmed = line.trim();
        if (trimmed.startsWith('import ') || trimmed.startsWith('from ')) {
          forbiddenImports.forEach((forbidden) => {
            if (trimmed.includes(forbidden)) {
              violations.push({
                file: path.relative(path.resolve(__dirname, '..'), filePath),
                line: trimmed,
              });
            }
          });
        }
      });
    });

    expect(violations).toEqual([]);
  });
});
