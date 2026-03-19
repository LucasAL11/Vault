namespace Application.Cryptography.Constraints;

/// <summary>
/// Gadgets padrao para constraints aritmeticas (R1CS/PLONK-friendly).
/// Tudo expresso com +, -, * e equalidades a zero.
/// </summary>
public static class StandardGadgets
{
    /// <summary>Garante que v e booleano: v in {0,1}.</summary>
    public static void Bool(ConstraintBuilder b, Var v) => ConstraintBuilder.Bool(b, v);

    /// <summary>Range check via decomposicao em bits. Retorna a lista de bits.</summary>
    public static IReadOnlyList<Var> RangeCheckBits(ConstraintBuilder b, Var value, int bits, string prefix)
    {
        var bitVars = new List<Var>(bits);
        var terms = new List<string>(bits);
        for (int i = 0; i < bits; i++)
        {
            var bit = b.NewVar($"{prefix}{i}");
            Bool(b, bit);
            bitVars.Add(bit);
            terms.Add($"{(1 << i)}*{bit.Name}");
        }
        b.EqZero($"{value.Name} - ({string.Join(" + ", terms)})");
        return bitVars;
    }

    /// <summary>
    /// Gadget de comparacao: retorna lt (1 se a &lt; b, 0 caso contrario) usando borrow.
    /// bits define o limite (0 &lt;= a,b &lt; 2^bits).
    /// </summary>
    public static Var LessThan(ConstraintBuilder b, Var a, Var c, int bits, string prefix)
    {
        var borrow = b.NewVar($"{prefix}borrow");
        Bool(b, borrow);

        var diff = b.NewVar($"{prefix}diff");
        b.EqZero($"{diff.Name} - ({a.Name} - {c.Name} + {1 << bits}*{borrow.Name})");

        RangeCheckBits(b, diff, bits, $"{prefix}d_bit_");

        // borrow = 1 => a < c, borrow = 0 => a >= c
        return borrow;
    }

    /// <summary>Retorna ge = 1 se a >= b, 0 caso contrario (reuso de LessThan).</summary>
    public static Var GreaterOrEqual(ConstraintBuilder b, Var a, Var c, int bits, string prefix)
    {
        var lt = LessThan(b, a, c, bits, prefix);
        var ge = b.NewVar($"{prefix}ge");
        b.EqZero($"{ge.Name} - (1 - {lt.Name})");
        return ge;
    }

    /// <summary>Inverso seguro: inv e tal que v*inv = 1. Forca v != 0.</summary>
    public static Var InverseNonZero(ConstraintBuilder b, Var v, string prefix)
    {
        var inv = b.NewVar($"{prefix}inv");
        b.EqZero($"{v.Name}*{inv.Name} - 1");
        return inv;
    }

    /// <summary>
    /// IsZero gadget: retorna z (1 se v == 0, 0 se nao) e inv (so valido quando v != 0).
    /// Constraints: v*inv = 1 - z ; v*z = 0 ; z boolean.
    /// </summary>
    public static (Var z, Var inv) IsZero(ConstraintBuilder b, Var v, string prefix)
    {
        var z = b.NewVar($"{prefix}is_zero");
        Bool(b, z);

        var inv = b.NewVar($"{prefix}inv");
        b.EqZero($"{v.Name}*{inv.Name} - (1 - {z.Name})");
        b.EqZero($"{v.Name}*{z.Name}");

        return (z, inv);
    }

    /// <summary>Selecao condicional r = s?a:b.</summary>
    public static Var Select(ConstraintBuilder b, Var s, Var a, Var c, string name) =>
        ConstraintBuilder.Select(b, s, a, c, name);

    /// <summary>Wire de soma: r = x + y.</summary>
    public static Var Add(ConstraintBuilder b, Var x, Var y, string name)
    {
        var r = b.NewVar(name);
        b.EqZero($"{r.Name} - ({x.Name}+{y.Name})");
        return r;
    }

    /// <summary>Wire de subtracao: r = x - y.</summary>
    public static Var Sub(ConstraintBuilder b, Var x, Var y, string name)
    {
        var r = b.NewVar(name);
        b.EqZero($"{r.Name} - ({x.Name}-{y.Name})");
        return r;
    }

    /// <summary>Wire de multiplicacao: r = x * y.</summary>
    public static Var Mul(ConstraintBuilder b, Var x, Var y, string name)
    {
        var r = b.NewVar(name);
        b.EqZero($"{r.Name} - ({x.Name}*{y.Name})");
        return r;
    }
}