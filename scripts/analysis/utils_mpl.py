"""
Small Matplotlib util: set nice default parameters (fonts, sizes, etc.).
"""

__author__ = "Thomas Guillod"
__copyright__ = "Thomas Guillod - Dartmouth College"
__license__ = "Mozilla Public License Version 2.0"

import matplotlib.pyplot as plt


def set_global():
    """
    Set the global Matplotlib options.
    """

    # set the font family
    plt.rcParams["font.size"] = 9.0
    plt.rcParams["font.family"] = "Times New Roman"
    plt.rcParams["mathtext.default"] = "regular"

    # set the axes parameters
    plt.rcParams["axes.linewidth"] = 1.0
    plt.rcParams["axes.labelsize"] = 9.0
    plt.rcParams["axes.titlesize"] = 10.0
    plt.rcParams["axes.labelpad"] = 8.0
    plt.rcParams["axes.labelweight"] = "bold"
    plt.rcParams["axes.titleweight"] = "bold"

    # set the legend parameters
    plt.rcParams["legend.edgecolor"] = "k"
    plt.rcParams["legend.fancybox"] = False
    plt.rcParams["legend.framealpha"] = 1.0
    plt.rcParams["legend.fontsize"] = 9.0
