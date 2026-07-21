"""
Chart Generator - Creates matplotlib charts for TDARE insights
"""

import matplotlib
# Use QtAgg backend which works with both PySide6 and PyQt5
try:
    matplotlib.use('QtAgg')
except:
    matplotlib.use('Qt5Agg')
    
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

# Try PySide6 backend first, fallback to Qt5
try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
except ImportError:
    try:
        from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
    except ImportError:
        from matplotlib.backends.backend_agg import FigureCanvasAgg as FigureCanvas

import numpy as np

from ui.constants import (
    CYAN_400, TEAL_400, RED_500, ORANGE_500, AMBER_500, EMERALD_500,
    SLATE_800, SLATE_400, WHITE
)


class ChartCanvas(FigureCanvas):
    """Matplotlib canvas for PySide6"""
    
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig = Figure(figsize=(width, height), dpi=dpi, facecolor='#1e293b')
        super().__init__(self.fig)
        self.setParent(parent)
        
        # Set dark theme
        self.fig.patch.set_facecolor('#1e293b')
        self.fig.patch.set_alpha(0.9)


class LineChartWidget(ChartCanvas):
    """Line chart widget for alerts/threat score"""
    
    def __init__(self, data: list, parent=None):
        super().__init__(parent, width=6, height=3, dpi=80)
        self.data = data
        self._create_chart()
    
    def _create_chart(self):
        """Create line chart"""
        ax = self.fig.add_subplot(111)
        ax.set_facecolor('#1e293b')
        
        if not self.data:
            ax.text(0.5, 0.5, 'No data available', 
                   ha='center', va='center', 
                   color=SLATE_400.name(), fontsize=12)
            ax.set_xticks([])
            ax.set_yticks([])
            return
        
        days = [d['day'] for d in self.data]
        alerts = [d['alerts'] for d in self.data]
        scores = [d['score'] for d in self.data]
        
        # Create line chart
        ax2 = ax.twinx()  # Second y-axis for score
        
        line1 = ax.plot(days, alerts, marker='o', linewidth=2, 
                       color=CYAN_400.name(), label='Alerts', markersize=6)
        line2 = ax2.plot(days, scores, marker='s', linewidth=2, 
                        color=TEAL_400.name(), label='Threat Score', markersize=6)
        
        # Styling
        ax.set_xlabel('Day', color=SLATE_400.name(), fontsize=10)
        ax.set_ylabel('Alerts', color=CYAN_400.name(), fontsize=10)
        ax2.set_ylabel('Threat Score', color=TEAL_400.name(), fontsize=10)
        
        ax.tick_params(colors=SLATE_400.name(), labelsize=9)
        ax2.tick_params(colors=SLATE_400.name(), labelsize=9)
        
        ax.grid(True, alpha=0.2, color=SLATE_400.name())
        ax.set_facecolor('#1e293b')
        ax2.set_facecolor('#1e293b')
        
        # Legend
        lines = line1 + line2
        labels = [l.get_label() for l in lines]
        ax.legend(lines, labels, loc='upper left', 
                 facecolor='#1e293b', edgecolor='none',
                 labelcolor=WHITE.name(), fontsize=9)
        
        self.fig.tight_layout()


class PieChartWidget(ChartCanvas):
    """Pie chart widget for severity distribution"""
    
    def __init__(self, data: list, parent=None):
        super().__init__(parent, width=5, height=4, dpi=80)
        self.data = data
        self._create_chart()
    
    def _create_chart(self):
        """Create pie chart"""
        ax = self.fig.add_subplot(111)
        ax.set_facecolor('#1e293b')
        
        if not self.data:
            ax.text(0.5, 0.5, 'No data available', 
                   ha='center', va='center', 
                   color=SLATE_400.name(), fontsize=12)
            ax.set_xticks([])
            ax.set_yticks([])
            return
        
        labels = [d['name'] for d in self.data]
        values = [d['value'] for d in self.data]
        colors = [d['color'] for d in self.data]
        
        # Create pie chart
        wedges, texts, autotexts = ax.pie(
            values, 
            labels=labels,
            colors=colors,
            autopct='%1.0f',
            startangle=90,
            textprops={'color': WHITE.name(), 'fontsize': 9}
        )
        
        # Style percentage text
        for autotext in autotexts:
            autotext.set_color(WHITE.name())
            autotext.set_fontweight('bold')
        
        # Style labels
        for text in texts:
            text.set_color(SLATE_400.name())
            text.set_fontsize(9)
        
        ax.set_facecolor('#1e293b')
        self.fig.tight_layout()


class BarChartWidget(ChartCanvas):
    """Bar chart widget for event distribution"""
    
    def __init__(self, data: dict, title: str, parent=None):
        super().__init__(parent, width=6, height=3, dpi=80)
        self.data = data
        self.title = title
        self._create_chart()
    
    def _create_chart(self):
        """Create bar chart"""
        ax = self.fig.add_subplot(111)
        ax.set_facecolor('#1e293b')
        
        if not self.data:
            ax.text(0.5, 0.5, 'No data available', 
                   ha='center', va='center', 
                   color=SLATE_400.name(), fontsize=12)
            ax.set_xticks([])
            ax.set_yticks([])
            return
        
        labels = list(self.data.keys())
        values = list(self.data.values())
        
        # Create bar chart
        bars = ax.bar(labels, values, color=CYAN_400.name(), alpha=0.8)
        
        # Add value labels on bars
        for bar in bars:
            height = bar.get_height()
            ax.text(bar.get_x() + bar.get_width()/2., height,
                   f'{int(height)}',
                   ha='center', va='bottom',
                   color=WHITE.name(), fontsize=9, fontweight='bold')
        
        ax.set_title(self.title, color=WHITE.name(), fontsize=11, fontweight='bold', pad=10)
        ax.set_ylabel('Count', color=SLATE_400.name(), fontsize=10)
        ax.set_xlabel('Category', color=SLATE_400.name(), fontsize=10)
        
        ax.tick_params(colors=SLATE_400.name(), labelsize=9)
        ax.set_xticklabels(labels, rotation=45, ha='right')
        
        ax.grid(True, alpha=0.2, color=SLATE_400.name(), axis='y')
        ax.set_facecolor('#1e293b')
        
        self.fig.tight_layout()

