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

  it('domain layers must have ZERO imports from @prisma/client, @nestjs/*, or express', () => {
    const allFiles = getFilesRecursively(domainDir);
    const domainFiles = allFiles.filter((f) => f.includes(`${path.sep}domain${path.sep}`));

    expect(domainFiles.length).toBeGreaterThan(0);

    const forbiddenImports = ['@prisma/client', '@nestjs', 'express'];
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

  it('modules/<ctxA> must NEVER directly import concrete repository or infrastructure classes from modules/<ctxB>/infrastructure', () => {
    const modulesDir = path.resolve(__dirname, '../src/modules');
    const moduleNames = fs.readdirSync(modulesDir).filter((name) => {
      const full = path.join(modulesDir, name);
      return fs.statSync(full).isDirectory();
    });

    const crossContextViolations: { file: string; line: string; importedModule: string }[] = [];

    moduleNames.forEach((ctxA) => {
      const ctxAFiles = getFilesRecursively(path.join(modulesDir, ctxA));

      ctxAFiles.forEach((filePath) => {
        const content = fs.readFileSync(filePath, 'utf-8');
        const lines = content.split('\n');

        lines.forEach((line) => {
          const trimmed = line.trim();
          if (trimmed.startsWith('import ') || trimmed.startsWith('from ')) {
            moduleNames.forEach((ctxB) => {
              if (ctxA !== ctxB) {
                const crossModuleInfraPattern = new RegExp(`['"].*[/\\\\]${ctxB}[/\\\\]infrastructure[/\\\\].*['"]`);
                if (crossModuleInfraPattern.test(trimmed)) {
                  crossContextViolations.push({
                    file: path.relative(path.resolve(__dirname, '..'), filePath),
                    line: trimmed,
                    importedModule: ctxB,
                  });
                }
              }
            });
          }
        });
      });
    });

    expect(crossContextViolations).toEqual([]);
  });
});
