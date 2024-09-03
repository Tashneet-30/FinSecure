from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .forms import (
    LoginForm, RegisterForm, PersonalForm, IncomeForm, ExpensesForm, 
    SavingsForm, FinancialGoalsForm, RiskProfileForm, ReviewForm
)
from .models import Personal, Income, Expenses, Savings, Assets, FinancialGoals, RiskProfile
from django.contrib.auth.models import User

def logout_view(request):
    logout(request)
    return redirect('landing')

def landing(request):
    if request.user.is_authenticated:
        return redirect('financial_data_view')

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
    form = RegisterForm(data=request.POST or None)

    if request.method == 'POST':
        if form.is_valid():
            user = User.objects.create_user(
                username=form.cleaned_data['username'], 
                password=form.cleaned_data['password1']
            )
            user.save()
            
            # Create related objects
            Personal.objects.create(user=user)
            Income.objects.create(user=user)
            Expenses.objects.create(user=user)
            Savings.objects.create(user=user)
            Assets.objects.create(user=user)
            FinancialGoals.objects.create(user=user)
            RiskProfile.objects.create(user=user)

            login(request, user)
            messages.success(request, 'Registration successful. Please log in.')
            return redirect('landing')
        else:
            messages.error(request, 'Invalid registration details')

    return render(request, 'register.html', {'form': form})

@login_required
def financial_data_view(request):
    if request.method == 'POST':
        # Save the data based on the step
        step = request.POST.get('step')
        if step == '1':
            form = PersonalForm(request.POST, instance=request.user.personal)
        elif step == '2':
            form = IncomeForm(request.POST, instance=request.user.income)
        elif step == '3':
            form = ExpensesForm(request.POST, instance=request.user.expenses)
        elif step == '4':
            form = SavingsForm(request.POST, instance=request.user.savings)
        elif step == '5':
            form = FinancialGoalsForm(request.POST, instance=request.user.financialgoals)
        elif step == '6':
            form = RiskProfileForm(request.POST, instance=request.user.riskprofile)
        elif step == '7':
            form = ReviewForm(request.POST)
            if form.is_valid():
                messages.success(request, 'Data successfully saved!')
                return redirect('some_success_url')
            else:
                messages.error(request, 'Invalid step')

        if form and form.is_valid():
            form.save()
            return JsonResponse({'status': 'success'})
        else:
            errors = form.errors if form else {'step': 'Invalid step'}
            return JsonResponse({'status': 'error', 'errors': errors})
    else:
        # Initial load or error handling
        return render(request, 'data.html')
