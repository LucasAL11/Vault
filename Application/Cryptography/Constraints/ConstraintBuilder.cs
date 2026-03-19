using System.Collections.Generic;
using System.Linq;

namespace Application.Cryptography.Constraints;

/// <summary>
/// Construtor de constraints aritméticas (expr == 0) usando apenas +, -, *.
/// Gera variáveis auxiliares e utilitários para booleanos, range (bit-decompose) e seleção condicional.
/// </summary>
public sealed class ConstraintBuilder
{
    private readonly List<Constraint> _constraints = new();
    private int _varCounter;

    public IReadOnlyCollection<Constraint> Constraints => _constraints;

    public Var NewVar(string prefix) => new($"{prefix}_{++_varCounter}");

    public void EqZero(string expr) => _constraints.Add(new Constraint(expr));

    public static void Bool(ConstraintBuilder builder, Var v) =>
        builder.EqZero($"{v.Name}*({v.Name}-1)");

    public static void DecomposeBits(ConstraintBuilder builder, Var value, int bits, string prefix)
    {
        var terms = Enumerable.Range(0, bits).Select(i =>
        {
            var bit = builder.NewVar($"{prefix}{i}");
            Bool(builder, bit);
            return $"{(1 << i)}*{bit.Name}";
        });

        builder.EqZero($"{value.Name} - ({string.Join(" + ", terms)})");
    }

    public static Var Select(ConstraintBuilder builder, Var s, Var a, Var bVar, string name)
    {
        var r = builder.NewVar(name);
        builder.EqZero($"{r.Name} - ({s.Name}*{a.Name} + (1-{s.Name})*{bVar.Name})");
        return r;
    }
}

public sealed record Var(string Name);
