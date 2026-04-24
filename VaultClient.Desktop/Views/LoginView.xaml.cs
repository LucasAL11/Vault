using System;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Threading;
using VaultClient.Desktop.ViewModels;

namespace VaultClient.Desktop.Views;

public partial class LoginView : UserControl
{
    // ── Full messages for each log line ─────────────────────────────────
    private static readonly string[] _messages =
    {
        "sentil.core booted · node plastcor-dc01",
        "ldap://dc.plastcor.corp:636 + tls handshake ok",
        "HSM online · vault sealed",
        // AUTH message split: static part stays in XAML, dots handled separately
    };

    // Dots cycling state
    private static readonly string[] _dotFrames = { ".", "..", "...", "" };
    private int _dotFrame;
    private DispatcherTimer? _dotTimer;
    private DispatcherTimer? _blinkTimer;

    public LoginView()
    {
        InitializeComponent();

        LoginButton.Click += OnLoginClick;
        PasswordBox.KeyDown += (_, e) =>
        {
            if (e.Key == Key.Return) OnLoginClick(this, new RoutedEventArgs());
        };

        Loaded += (_, _) => StartBootAnimation();
        IsVisibleChanged += OnVisibilityChanged;
    }

    // ── Boot animation entry point ───────────────────────────────────────

    private void StartBootAnimation()
    {
        // Stamp timestamps relative to now
        var now = DateTime.Now;
        LogTs0.Text = now.AddSeconds(-6).ToString("HH:mm:ss");
        LogTs1.Text = now.AddSeconds(-5).ToString("HH:mm:ss");
        LogTs2.Text = now.AddSeconds(-3).ToString("HH:mm:ss");
        LogTs3.Text = now.ToString("HH:mm:ss");

        // Pre-fill message text (typewriter handled via stagger for now)
        LogMsg0.Text = _messages[0];
        LogMsg1.Text = _messages[1];
        LogMsg2.Text = _messages[2];
        AuthDots.Text = "";

        // Staggered fade-in for each row
        var rows = new FrameworkElement[] { LogRow0, LogRow1, LogRow2, LogRow3, LogCursorRow };
        var delays = new[] { 350, 800, 1350, 1950, 2400 };

        for (int i = 0; i < rows.Length; i++)
        {
            var row = rows[i];
            var ms   = delays[i];

            var t = new DispatcherTimer(DispatcherPriority.Render)
            {
                Interval = TimeSpan.FromMilliseconds(ms)
            };
            t.Tick += (s, _) =>
            {
                if (s is DispatcherTimer dt) dt.Stop();
                FadeIn(row, 260);
            };
            t.Start();
        }

        // Cursor blink — starts after cursor row appears
        _blinkTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(2650) };
        _blinkTimer.Tick += (s, _) =>
        {
            if (s is DispatcherTimer dt) dt.Stop();
            StartCursorBlink();
        };
        _blinkTimer.Start();

        // Dots cycling — starts when AUTH row appears
        var dotsDelay = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(2000) };
        dotsDelay.Tick += (s, _) =>
        {
            if (s is DispatcherTimer dt) dt.Stop();
            StartDotsCycle();
        };
        dotsDelay.Start();
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    private static void FadeIn(FrameworkElement el, int durationMs)
    {
        var anim = new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(durationMs))
        {
            EasingFunction = new CubicEase { EasingMode = EasingMode.EaseOut }
        };
        el.BeginAnimation(OpacityProperty, anim);
    }

    private void StartCursorBlink()
    {
        var blink = new DoubleAnimation(1, 0, TimeSpan.FromMilliseconds(520))
        {
            AutoReverse     = true,
            RepeatBehavior  = RepeatBehavior.Forever,
            EasingFunction  = new CubicEase { EasingMode = EasingMode.EaseInOut }
        };
        LogCursorChar.BeginAnimation(OpacityProperty, blink);
    }

    private void StartDotsCycle()
    {
        _dotFrame = 0;
        _dotTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(420) };
        _dotTimer.Tick += (_, _) =>
        {
            _dotFrame = (_dotFrame + 1) % _dotFrames.Length;
            AuthDots.Text = _dotFrames[_dotFrame];
        };
        _dotTimer.Start();
    }

    private void StopAnimations()
    {
        _dotTimer?.Stop();
        _blinkTimer?.Stop();
    }

    // ── Restart animation when view becomes visible again ───────────────

    private void OnVisibilityChanged(object sender, DependencyPropertyChangedEventArgs e)
    {
        if ((bool)e.NewValue)
        {
            StopAnimations();

            // Reset all rows to invisible then replay
            foreach (var row in new FrameworkElement[] { LogRow0, LogRow1, LogRow2, LogRow3, LogCursorRow })
                row.BeginAnimation(OpacityProperty, new DoubleAnimation(0, TimeSpan.Zero));

            StartBootAnimation();
        }
        else
        {
            StopAnimations();
        }
    }

    // ── Login click ──────────────────────────────────────────────────────

    private void OnLoginClick(object sender, RoutedEventArgs e)
    {
        if (DataContext is LoginViewModel vm)
            vm.LoginCommand.Execute(PasswordBox.Password);
    }
}
