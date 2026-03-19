using System.Collections.Generic;

namespace Application.Cryptography.Constraints;

/// <summary>
/// Exemplo de R1CS: if (a >= b) z = (x + y)/b else z = x - y.
/// Cada operacao vira 1 linha R1CS (&lt;A,w&gt*&lt;B,w&gt=&lt;C,w&gt). Range check simplificado.
/// </summary>
public static class ExampleR1csFactory
{
    public static (IReadOnlyList<R1csBuilder.R1csConstraint> constraints,
                   IReadOnlyDictionary<string,int> wires) Build(string a, string b, string x, string y)
    {
        var r1 = new R1csBuilder();

        // borrow flag u (boolean)
        var u = "u";
        r1.Bool(u);

        // t1 = a - b
        var t1 = "t1";
        r1.SubFn(t1, a, b);

        // scaledBorrow = u * 2^16
        var scaledBorrow = "scaledBorrow";
        r1.MulConst(scaledBorrow, u, 1 << 16);

        // d = t1 + scaledBorrow  (a - b + 2^16*u)
        var d = "d";
        r1.AddFn(d, t1, scaledBorrow);
        // (range check de d omitido aqui; adicionar bits se necessario)

        // s = 1 - u   (s=1 se a>=b)
        var negU = "negU";
        r1.MulConst(negU, u, -1);
        var s = "s";
        r1.AddConst(s, negU, 1);

        // inv_b tal que b*inv_b = 1
        var invB = "inv_b";
        r1.Inverse(invB, b);

        // sum = x + y ; diff = x - y
        var sum = "sum_xy";
        r1.AddFn(sum, x, y);

        var diff = "diff_xy";
        r1.SubFn(diff, x, y);

        // divBranch = sum * inv_b
        var divBranch = "div_branch";
        r1.Mul(divBranch, sum, invB);

        // z = s ? divBranch : diff   => z - diff = s*(divBranch - diff)
        var z = "z";
        r1.Select(z, s, divBranch, diff);

        return (r1.Constraints, r1.WireIndex);
    }
}
