# Runbook: BLS12-381 calculo completo (logica + execucao)

> STATUS: LEGADO (fora do escopo do MVP sem ZK desde 2026-03-23).
> Documento mantido apenas para referencia tecnica historica.
> Rotas ZK foram removidas do runtime da API no caminho MVP.

## Escopo
Este documento descreve a logica completa do calculo de pairing no projeto, do inicio ao fim:
- campo primo e campos de extensao
- pontos em G1/G2 e validacoes de subgroup
- serializacao comprimida canonica
- Miller loop
- final exponentiation (easy part + hard part)
- projecao em GT e checagem de bilinearidade

## 1) Dominio matematico
Parametros principais (arquivo `Infrastructure/Zk/Crypto/Bls12381Constants.cs`):
- `p`: modulo do campo primo `Fp`
- `r`: ordem do subgroup primo (tambem modulo de `Fr`)
- `x`: parametro BLS (`|x| = 0xD201000000010000`, com sinal negativo no dominio BLS12-381)
- `finalExponent = (p^12 - 1) / r`

Campos:
- `Fp`: aritmetica modular em `mod p`
- `Fp2 = Fp[u] / (u^2 + 1)`  (no codigo: `u^2 = -1`)
- `Fp6 = Fp2[v] / (v^3 - (u+1))`
- `Fp12 = Fp6[w] / (w^2 - v)`

## 2) Curvas e grupos
Equacoes:
- `G1`: `y^2 = x^3 + 4` sobre `Fp`
- `G2`: `y^2 = x^3 + 4(u+1)` sobre `Fp2` (twist)

Operacoes de ponto (afins):
- soma: `lambda = (y2 - y1)/(x2 - x1)`, depois `xr`, `yr`
- dobra: `lambda = (3*x1^2)/(2*y1)`, depois `xr`, `yr`
- escalar: double-and-add

Validacoes aplicadas antes do pairing:
- nao infinito
- on-curve
- em subgroup primo
  - G1: checagem por `r*P == O`
  - G2: checagem rapida por endomorfismo `psi` + fallback seguro

## 3) Serializacao comprimida canonica
Formato comprimido:
- G1: 48 bytes
- G2: 96 bytes

Regras:
- bit de compressao obrigatorio
- bit de infinito tratado explicitamente
- bit de sinal lexicografico para escolher raiz `y`
- reconstruir `y` via `sqrt` de `x^3 + b`
- validar on-curve e subgroup apos decode

## 4) Miller loop (logica)
Implementacao em `Infrastructure/Zk/Crypto/PairingReferenceEngine.cs`.

Fluxo:
1. iniciar `f = 1` em `Fp12`, `R = Q`
2. iterar bits de `|x|` (MSB -> LSB, ignorando o primeiro bit):
   - `f = f^2 * l_{R,R}(P)`  (linha da dobra)
   - `R = 2R`
   - se bit=1:
     - `f = f * l_{R,Q}(P)`  (linha da soma)
     - `R = R + Q`

Onde:
- `l_{A,B}(P)` e a avaliacao da reta definida por `A,B` no ponto `P`
- resultado intermediario fica em `Fp12`

## 5) Final exponentiation (logica)
Objetivo: projetar resultado de Miller para `GT` (subgroup de ordem `r`).

### Easy part
Usa decomposicao:
- `(p^12 - 1)/r = ((p^6 - 1)(p^2 + 1)) * hardPart`

No codigo:
- `t0 = conjugate(f) * inverse(f)`   (equivale a `f^(p^6-1)`)
- `easy = frobenius^2(t0) * t0`      (multiplica por `p^2 + 1`)

### Hard part
- elevar `easy` para `FinalExponentHard`
- no projeto: `PowCyclotomicWindowed(..., window=3)` para hard part
- API dedicada de `exp by x`: `ExpByBlsX()` (suporta sinal de `x` via conjugacao)

## 6) Projecao GT e bilinearidade
`Pair(P,Q) = FinalExponentiation(MillerLoop(P,Q))`.

Propriedade checada no runner/testes:
- `e([s]P,[t]Q) == e(P,Q)^(s*t)`

## 7) Sequencia end-to-end do runner `--calc`
Runner: `tests/Infrastructure.Benchmarks/FullPairingCalculationRunner.cs`

Etapas:
1. valida dominio e geradores (`on curve` + `subgroup`)
2. roundtrip de serializacao comprimida G1/G2
3. constroi `P=[a]G1`, `Q=[b]G2`
4. executa Miller loop
5. executa final exponentiation (otimizada) e compara com exponenciacao direta
6. valida bilinearidade em GT

## 8) Como executar
Build:
```powershell
dotnet build tests\Infrastructure.Benchmarks\Infrastructure.Benchmarks.csproj -c Release
```

Calculo completo:
```powershell
dotnet run -c Release --project tests\Infrastructure.Benchmarks\Infrastructure.Benchmarks.csproj -- --calc
```

Benchmark (`Pow` vs `PowWindowed`):
```powershell
dotnet run -c Release --project tests\Infrastructure.Benchmarks\Infrastructure.Benchmarks.csproj
```

## 9) Criterios de sucesso do `--calc`
- `G1 on curve: True`
- `G2 on curve: True`
- `G1 subgroup: True`
- `G2 subgroup (fast): True`
- roundtrip G1/G2 = `True`
- `Miller value is one: False`
- `Final exp matches direct: True`
- `Bilinearity: True`

## 10) Limites atuais
- Implementacao in-process para validacao de engenharia.
- Foco em corretude e rastreabilidade do fluxo; nao foi desenhada para hardening de side-channel em nivel de biblioteca criptografica especializada.
