using System.Collections.Generic;
using System.Globalization;
using System.Numerics;

namespace Application.Cryptography.Constraints;

/// <summary>
/// Builder de R1CS: cada constraint eh (&lt;A,w&gt) * (&lt;B,w&gt) = (&lt;C,w&gt),
/// com vetores esparsos. Mantem mapa de variaveis -> indices e gera helpers
/// de operacoes basicas em 1 linha cada.
/// </summary>
public sealed class R1csBuilder
{
    public const string ConstantWireName = "1";
    public const int ConstantWireId = 0;

    public static readonly BigInteger Bls12_381ScalarFieldPrime = BigInteger.Parse(
        "52435875175126190479447740508185965837690552500527637822603658699938581184513",
        CultureInfo.InvariantCulture);

    public sealed record SparseVec(Dictionary<int, BigInteger> Terms);
    public sealed record R1csConstraint(SparseVec A, SparseVec B, SparseVec C);

    private readonly Dictionary<string, int> _ids = new();
    private readonly List<R1csConstraint> _constraints = new();
    private readonly BigInteger _modulus;
    private int _nextId = 1; // 0 reservado para wire constante 1

    public R1csBuilder(BigInteger? modulus = null)
    {
        _modulus = modulus ?? Bls12_381ScalarFieldPrime;
        if (_modulus <= BigInteger.One)
        {
            throw new ArgumentOutOfRangeException(nameof(modulus), "Field modulus must be greater than 1.");
        }

        _ids[ConstantWireName] = ConstantWireId;
    }

    public int IdOf(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
        {
            throw new ArgumentException("Wire name is required.", nameof(name));
        }

        if (_ids.TryGetValue(name, out var id)) return id;
        id = _nextId++;
        _ids[name] = id;
        return id;
    }

    public IReadOnlyDictionary<string, int> WireIndex => _ids;
    public IReadOnlyList<R1csConstraint> Constraints => _constraints;
    public BigInteger Modulus => _modulus;
    public BigInteger Mod(BigInteger value) => ModP(value);

    private SparseVec Vec(params (int idx, BigInteger coeff)[] terms)
    {
        var d = new Dictionary<int, BigInteger>();
        foreach (var (idx, coeff) in terms)
        {
            var normalized = ModP(coeff);
            if (normalized.IsZero) continue;

            if (d.TryGetValue(idx, out var prev))
            {
                var sum = ModP(prev + normalized);
                if (sum.IsZero) d.Remove(idx);
                else d[idx] = sum;
            }
            else
            {
                d[idx] = normalized;
            }
        }

        return new SparseVec(d);
    }

    private BigInteger ModP(BigInteger value)
    {
        var normalized = value % _modulus;
        if (normalized.Sign < 0) normalized += _modulus;
        return normalized;
    }

    private void Add(R1csConstraint c) => _constraints.Add(c);

    /// <summary>r = x * y  => A:{x}, B:{y}, C:{r}</summary>
    public void Mul(string r, string x, string y)
    {
        Add(new R1csConstraint(
            Vec((IdOf(x), BigInteger.One)),
            Vec((IdOf(y), BigInteger.One)),
            Vec((IdOf(r), BigInteger.One))));
    }

    /// <summary>r = k * x => A:{x}, B:{1:k}, C:{r}</summary>
    public void MulConst(string r, string x, BigInteger k)
    {
        Add(new R1csConstraint(
            Vec((IdOf(x), BigInteger.One)),
            Vec((IdOf(ConstantWireName), k)),
            Vec((IdOf(r), BigInteger.One))));
    }

    /// <summary>r = x + y  => (x+y)*1 = r</summary>
    public void AddFn(string r, string x, string y)
    {
        Add(new R1csConstraint(
            Vec((IdOf(x), BigInteger.One), (IdOf(y), BigInteger.One)),
            Vec((IdOf(ConstantWireName), BigInteger.One)),
            Vec((IdOf(r), BigInteger.One))));
    }

    /// <summary>r = x + k  => (x + k)*1 = r</summary>
    public void AddConst(string r, string x, BigInteger k)
    {
        Add(new R1csConstraint(
            Vec((IdOf(x), BigInteger.One), (IdOf(ConstantWireName), k)),
            Vec((IdOf(ConstantWireName), BigInteger.One)),
            Vec((IdOf(r), BigInteger.One))));
    }

    /// <summary>r = x - y  => (x - y)*1 = r</summary>
    public void SubFn(string r, string x, string y)
    {
        Add(new R1csConstraint(
            Vec((IdOf(x), BigInteger.One), (IdOf(y), -BigInteger.One)),
            Vec((IdOf(ConstantWireName), BigInteger.One)),
            Vec((IdOf(r), BigInteger.One))));
    }

    /// <summary>r = c (const) => 1*1 = r - c (move const p/ C)</summary>
    public void Const(string r, BigInteger constant)
    {
        Add(new R1csConstraint(
            Vec((IdOf(ConstantWireName), BigInteger.One)),
            Vec((IdOf(ConstantWireName), BigInteger.One)),
            Vec((IdOf(r), BigInteger.One), (IdOf(ConstantWireName), -constant))));
    }

    /// <summary>Boolean: v in {0,1} => v*(v-1)=0</summary>
    public void Bool(string v)
    {
        Add(new R1csConstraint(
            Vec((IdOf(v), BigInteger.One)),
            Vec((IdOf(v), BigInteger.One), (IdOf(ConstantWireName), -BigInteger.One)),
            Vec()));
    }

    /// <summary>Selecao: r = s ? a : b  => r-b = s*(a-b)</summary>
    public void Select(string r, string s, string a, string b)
    {
        Add(new R1csConstraint(
            Vec((IdOf(s), BigInteger.One)),
            Vec((IdOf(a), BigInteger.One), (IdOf(b), -BigInteger.One)),
            Vec((IdOf(r), BigInteger.One), (IdOf(b), -BigInteger.One))));
    }

    /// <summary>Inv: x*inv = 1 (x != 0 assumido)</summary>
    public void Inverse(string inv, string x)
    {
        Add(new R1csConstraint(
            Vec((IdOf(x), BigInteger.One)),
            Vec((IdOf(inv), BigInteger.One)),
            Vec((IdOf(ConstantWireName), BigInteger.One))));
    }
}
