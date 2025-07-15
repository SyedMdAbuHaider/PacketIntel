from rich.progress import (
    Progress,
    BarColumn,
    TimeRemainingColumn,
    TimeElapsedColumn,
    TextColumn,
    MofNCompleteColumn
)

class AnalysisProgress:
    """Handles progress display during PCAP analysis"""
    
    def __init__(self):
        self.progress = Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            expand=True
        )
    
    def track_analysis(self, iterable, description="Analyzing"):
        """Track progress through an iterable"""
        with self.progress:
            task_id = self.progress.add_task(description, total=len(iterable))
            for item in iterable:
                yield item
                self.progress.update(task_id, advance=1)