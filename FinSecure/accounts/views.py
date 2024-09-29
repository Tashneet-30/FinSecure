from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.core.exceptions import ObjectDoesNotExist
from .forms import *
from .models import *


def logout_view(request):
    logout(request)
    return redirect('landing')

def landing(request):
    if request.user.is_authenticated:
        return redirect('submit_financial_data')

    form = LoginForm(data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = authenticate(
                username=form.cleaned_data['username'], 
                password=form.cleaned_data['password']
            )
            if user is not None:
                login(request, user)
                return redirect('financial_data_view')
            else:
                messages.error(request, 'Invalid username or password')
        else:
            messages.error(request, 'Invalid username or password')

    return render(request, 'landing.html', {'form': form})

def register(request):
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            print("User registered")
            messages.success(request, 'Registration successful. Please log in.')
            return redirect('landing')
        else:
            messages.error(request, 'Invalid registration details')
    
    else:
        form = RegisterForm()

    return render(request, 'register.html', {'form': form})

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ObjectDoesNotExist
from django.forms import ValidationError

@login_required
def submit_financial_data(request):
    try:
        personal_instance = Personal.objects.get(user=request.user)
        income_instance = Income.objects.get(user=request.user)
        expenses_instance = Expenses.objects.get(user=request.user)
        savings_instance = Savings.objects.get(user=request.user)
        assets_instance = Assets.objects.get(user=request.user)
        financial_goals_instance = FinancialGoals.objects.get(user=request.user)
        risk_profile_instance = RiskProfile.objects.get(user=request.user)

    except ObjectDoesNotExist:
        personal_instance = Personal(user=request.user)
        income_instance = Income(user=request.user)
        expenses_instance = Expenses(user=request.user)
        savings_instance = Savings(user=request.user)
        assets_instance = Assets(user=request.user)
        financial_goals_instance = FinancialGoals(user=request.user)
        risk_profile_instance = RiskProfile(user=request.user)

    if request.method == 'POST':
        post_data = request.POST.copy()
        post_data.setdefault('retirement_lifestyle', 'moderate')  # Default value for invalid choices

        post_data.setdefault('one_time_expenses', '0')
        post_data.setdefault('debt', '0')
        post_data.setdefault('retirement_savings', '0')
        post_data.setdefault('investments', '0')
        post_data.setdefault('return_on_investments', '0')
        post_data.setdefault('real_estates', '0')
        post_data.setdefault('vehicles', '0')
        post_data.setdefault('liabilities', '0')
        post_data.setdefault('other_assets', '0')

        personal_form = PersonalForm(post_data, instance=personal_instance)
        income_form = IncomeForm(post_data, instance=income_instance)
        expenses_form = ExpensesForm(post_data, instance=expenses_instance)
        savings_form = SavingsForm(post_data, instance=savings_instance)
        assets_form = AssetsForm(post_data, instance=assets_instance)
        financial_goals_form = FinancialGoalsForm(post_data, instance=financial_goals_instance)
        risk_profile_form = RiskProfileForm(post_data, instance=risk_profile_instance)

        if (personal_form.is_valid() and income_form.is_valid() and expenses_form.is_valid() and
                savings_form.is_valid() and assets_form.is_valid() and financial_goals_form.is_valid() and
                risk_profile_form.is_valid()):
            personal_form.save()
            income_form.save()
            expenses_form.save()
            savings_form.save()
            assets_form.save()
            financial_goals_form.save()
            risk_profile_form.save()

            return redirect('submit_financial_data')

    else:
        personal_form = PersonalForm(instance=personal_instance)
        income_form = IncomeForm(instance=income_instance)
        expenses_form = ExpensesForm(instance=expenses_instance)
        savings_form = SavingsForm(instance=savings_instance)
        assets_form = AssetsForm(instance=assets_instance)
        financial_goals_form = FinancialGoalsForm(instance=financial_goals_instance)
        risk_profile_form = RiskProfileForm(instance=risk_profile_instance)

    context = {
        'personal_form': personal_form,
        'income_form': income_form,
        'expenses_form': expenses_form,
        'savings_form': savings_form,
        'assets_form': assets_form,
        'financial_goals_form': financial_goals_form,
        'risk_profile_form': risk_profile_form,
    }

    return render(request, 'data.html', context)
