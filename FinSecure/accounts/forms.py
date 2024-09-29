from django import forms
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import Personal, Income, Expenses, Savings, Assets, FinancialGoals, RiskProfile


class LoginForm(forms.Form):
    username = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 mt-2 border-2 border-gray-400 rounded-md text-black',
            'placeholder': 'Username'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full p-2 mt-2 border-2 border-gray-400 rounded-md text-black',
            'placeholder': 'Password'
        })
    )


class RegisterForm(UserCreationForm):
    username = forms.CharField(
        max_length=100,
        widget=forms.TextInput(attrs={
            'class': 'w-full p-2 mt-2 border-2 border-gray-400 rounded-md text-black',
            'placeholder': 'Username'
        })
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full p-2 mt-2 border-2 border-gray-400 rounded-md text-black',
            'placeholder': 'Password'
        })
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'w-full p-2 mt-2 border-2 border-gray-400 rounded-md text-black',
            'placeholder': 'Confirm Password'
        })
    )

    class Meta:
        model = User
        fields = ['username', 'password1', 'password2']



class PersonalForm(forms.ModelForm):
    class Meta:
        model = Personal
        fields = ['name', 'email', 'phone', 'age', 'retirement_age', 'marital_status', 'dependents']

class IncomeForm(forms.ModelForm):
    class Meta:
        model = Income
        fields = ['monthly_income', 'other_sources', 'expected_salary_growth', 'employment_type', 'employer_contributions']

class ExpensesForm(forms.ModelForm):
    class Meta:
        model = Expenses
        fields = ['monthly_expenses', 'annual_expenses', 'one_time_expenses', 'debt']

class SavingsForm(forms.ModelForm):
    class Meta:
        model = Savings
        fields = ['current_savings', 'retirement_savings', 'investments', 'return_on_investments']

class AssetsForm(forms.ModelForm):
    class Meta:
        model = Assets
        fields = ['real_estates', 'vehicles', 'liabilities', 'other_assets']

class FinancialGoalsForm(forms.ModelForm):
    class Meta:
        model = FinancialGoals
        fields = ['retirement_lifestyle']

class RiskProfileForm(forms.ModelForm):
    class Meta:
        model = RiskProfile
        fields = ['risk_tolerance']
        
class ReviewForm(forms.Form):
    # Add fields relevant to the review process
    comments = forms.CharField(
        widget=forms.Textarea(attrs={
            'class': 'w-full p-2 mt-2 border-2 border-gray-400 rounded-md text-black',
            'placeholder': 'Enter your comments'
        })
    )
