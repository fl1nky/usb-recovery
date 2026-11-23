using System;
using UsbRecovery;

public static class RecoveryRunPresentationTests
{
    static int checks;
    static void Check(bool condition, string message)
    {
        checks++;
        if (!condition) throw new Exception(message);
    }
    public static int Main()
    {
        var view = new RecoveryRunPresentation();
        Check(!view.CanContinue && !view.Percent.HasValue, "Idle view invents neither a saved job nor a percentage");
        view.StartPhase("Создание образа", "Подготовка копирования");
        Check(view.Heading == "Создание образа" && !view.Percent.HasValue, "Acquisition preparation is visible before any scan event");
        view.Apply(new RecoveryStageProgress { Key = "text", Title = "Текст", State = "running", Completed = long.MaxValue / 2, Total = long.MaxValue });
        Check(view.Percent == 49, "Large byte counts do not overflow");
        Check(view.SaveText.Contains("ещё не подтверждена"), "Reading is not a checkpoint acknowledgement");
        view.Apply(new RecoveryStageProgress { Key = "text", Title = "Текст", State = "running", Completed = 3, Total = 4, CheckpointSequence = 7, ResumingCheckpoint = true });
        Check(view.Percent == 75 && view.SaveText.Contains("№7"), "Only confirmed checkpoint generation is shown");
        Check(view.ActionText.Contains("проверенной точки"), "Real continuation is distinguished from a new pass");
        view.RequestStop();
        view.StartPhase("Late phase", "Late detail");
        Check(view.Heading == "Останавливаем поиск", "Late phase changes cannot hide stop request");
        view.Apply(new RecoveryStageProgress { Key = "text", Title = "Текст", State = "running", Completed = 8, Total = 10, CheckpointSequence = 8 });
        Check(view.StopRequested && view.Heading == "Останавливаем поиск" && !view.CanContinue, "Late progress cannot hide pending stop or enable resume");
        Check(view.Percent == 80, "Confirmed progress can advance while stop completes");
        view.Apply(new RecoveryStageProgress { Key = "text", State = "cancelled", CheckpointSequence = 8 });
        Check(view.Percent == 80, "Terminal event without byte totals preserves measured progress");
        view.Finish(false, false, true, true);
        Check(view.CanContinue && !view.StopRequested && view.Heading == "Поиск остановлен", "Stopped saved job enables continuation only after stop finishes");
        Check(view.SaveText.Contains("повторный проход"), "Unsupported cursor methods are not promised exact resume");
        view.Reset();
        view.Apply(new RecoveryStageProgress { Key = "verify", State = "running", Completed = 12, Total = 0 });
        Check(!view.Percent.HasValue, "Unknown size remains indeterminate");
        view.Apply(new RecoveryStageProgress { Key = "photos", State = "reused" });
        Check(view.ProgressText.Contains("проверен"), "Reused completed stage is explicit");
        view.Finish(false, false, false, false);
        Check(!view.CanContinue && view.Heading == "Поиск прерван", "Missing saved state is not advertised as resumable");
        view.Finish(true, true, true, false);
        Check(!view.CanContinue && view.Heading == "Завершено с замечаниями" && !view.Percent.HasValue, "Warnings are not painted as clean completion");
        view.Apply(new RecoveryStageProgress { Key = "text", Title = "Late update", State = "running", Completed = 5, Total = 10 });
        Check(view.Heading == "Завершено с замечаниями" && !view.Percent.HasValue, "Late queued progress cannot reopen a completed view");
        view.Apply(null);
        Console.WriteLine("PASS RecoveryRunPresentation: " + checks + " checks; presentation state only, no GUI windows");
        return 0;
    }
}
