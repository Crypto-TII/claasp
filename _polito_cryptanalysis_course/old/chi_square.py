# This script is inspired by https://matteocourthoud.github.io/post/chisquared/
# Install dependencies as follows:
# sage -sh
# pip install pandas
# pip install seaborn
# pip install statsmodels

# from utils import *

import numpy as np
import scipy as sp
import pandas as pd

# Generate random data

def generate_data_dice(N=60, seed=1):
    np.random.seed(seed) # Set seed for replicability
    dice_numbers = [1,2,3,4,5,6]  # Dice numbers
    dice_throws = np.random.choice(dice_numbers, size=N)  # Actual dice throws
    data = pd.DataFrame({"dice number": dice_numbers,
                         "observed": [sum(dice_throws==n) for n in dice_numbers],
                         "expected": int(N / 6)})
    return data

data_dice = generate_data_dice()
print(data_dice)

# Compute test statistic

def compute_chi2_stat(data):
    return sum( (data.observed - data.expected)**2 / data.expected )

chi2_test_statistic = compute_chi2_stat(data_dice)
print(f'{chi2_test_statistic=}')

# How does a chi square distribution look like?

from scipy.stats import chi2
import matplotlib.pyplot as plt

def plot_test(x, test_statistic, df, non_rejection_area=0.95):
    '''
    x is the numpy range
    '''
    rejection_area = round(1 - non_rejection_area, 2) # round to 2 decimal numbers
    critical_value = chi2.ppf(non_rejection_area, df=df) # compute the percent point function (ppf) of 95% for the chi-squared distribution, which is essentially the inverse of the cumulative distribution function
    chi2_pdf = chi2.pdf(x, df=df)
    plt.plot(x, chi2_pdf);
    plt.fill_between(x[x>critical_value], chi2_pdf[x>critical_value], 
        color='r', alpha=0.4, label='rejection area = ' + str(rejection_area))
    plt.fill_between(x[x<critical_value], chi2_pdf[x<critical_value], 
        color='g', alpha=0.4, label='non-rejection area = ' + str(non_rejection_area))
    plt.axvline(test_statistic, color='k', label='chi2 test statistic = ' + str(round(test_statistic, 2)))
    plt.axvline(critical_value, color='r', label='critical value = ' + str(round(critical_value, 2)))
    plt.ylim(0, plt.ylim()[1])
    plt.legend();
    plt.show()

# Example 2 with significance level of 0.95 and 0.99

x = np.arange(0, 30, 0.001) # x-axis ranges from 0 to 30 with .001 steps
df = 5
plot_test(x, chi2_test_statistic, df=df)

data_dice = pd.DataFrame({"dice number": [1,2,3,4,5,6],
                         "observed": [5, 8, 9, 8, 10, 20],
                         "expected": 10})
chi2_test_statistic = compute_chi2_stat(data_dice)
plot_test(x, chi2_test_statistic, df=df)
plt.show()

data_dice = pd.DataFrame({"dice number": [1,2,3,4,5,6],
                         "observed": [5, 8, 9, 8, 10, 20],
                         "expected": 10})
chi2_test_statistic = compute_chi2_stat(data_dice)
plot_test(x, chi2_test_statistic, df=df, non_rejection_area=0.99)
plt.show()


#  Simulate the chi square distribution

def simulate_chi2stats(K, N, dgp):
    chi2_stats = [compute_chi2_stat(dgp(seed=k)) for k in range(K)]
    return np.array(chi2_stats)

chi2_stats = simulate_chi2stats(K=100, N=60, dgp=generate_data_dice)
plt.hist(chi2_stats, density=True, bins=30, alpha=0.3, color='C0');
plt.plot(x, chi2.pdf(x, df=df));
plt.show()


# Simulate a fair coin toss

df = 1
x = np.arange(0, 6, 0.001) # x-axis ranges from 0 to 30 with .001 steps
chi2_test_statistic = 5.76
plot_test(x, chi2_test_statistic, df=df)
pvalue = 1 - chi2.cdf(chi2_test_statistic)
