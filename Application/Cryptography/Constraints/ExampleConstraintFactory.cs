using Application.Cryptography.Constraints;

namespace Application.Cryptography;

/// <summary>
/// Exemplo de geracao de constraints com gadgets padrao:
/// if (a >= b) z = (x + y) / b else z = x - y
/// Apenas +, -, *; cada etapa vira 1-2 constraints e reusa wires.
/// </summary>
public static class ExampleConstraintFactory
{
    public static IReadOnlyCollection<Constraint> Build(Var a, Var b, Var x, Var y)
    {
        var c = new ConstraintBuilder();

        // Range check: a, b em 16 bits
        StandardGadgets.RangeCheckBits(c, a, 16, "a_bit_");
        StandardGadgets.RangeCheckBits(c, b, 16, "b_bit_");

        // a - b + 2^16 * u = d   (u eh borrow; u=0 => a>=b)
        var u = StandardGadgets.LessThan(c, a, b, 16, "cmp_"); // u=1 se a<b
        var s = c.NewVar("s");
        c.EqZero($"{s.Name} - (1 - {u.Name})"); // s=1 se a>=b

        // inverso de b (garante b != 0): b*inv_b = 1
        var invB = StandardGadgets.InverseNonZero(c, b, "b_");

        // wires para reuso
        var sumXY = StandardGadgets.Add(c, x, y, "sum_xy");
        var diffXY = StandardGadgets.Sub(c, x, y, "diff_xy");
        var divBranch = StandardGadgets.Mul(c, sumXY, invB, "div_branch"); // (x+y)/b => (x+y)*inv_b

        // selecao condicional
        var z = StandardGadgets.Select(c, s, divBranch, diffXY, "z");

        return c.Constraints;
    }
}
