from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib import messages
from .forms import *
from django.contrib.auth import logout
from django.contrib.auth.models import User
from django.contrib.auth.decorators import login_required
from .forms import PersonalForm, IncomeForm, ExpensesForm, SavingsForm, AssetsForm, FinancialGoalsForm, RiskProfileForm
# Create your views here.
from django.http import JsonResponse

def logout_view(request):
    logout(request)
    return redirect('landing')

def landing(request):
    # If the user is already authenticated, redirect them to the financial profile view
    # if request.user.is_authenticated:
    #     return redirect('financial_profile_view')

    form = LoginForm(data=request.POST or None)
    if request.method == 'POST':
        if form.is_valid():
            user = authenticate(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            if user is not None:
                login(request, user)
                return redirect('financial_profile_view')  # Redirect to financial profile view after login
            else:
                messages.error(request, 'Invalid username or password')
        else:
            messages.error(request, 'Invalid username or password')

    return render(request, 'landing.html', {'form': form})

def register(request):
    form = RegisterForm(data=request.POST or None)  # Initialize the form for both GET and POST

    if request.method == 'POST':
        if form.is_valid():
            user = User.objects.create_user(username=form.cleaned_data['username'], password=form.cleaned_data['password'])
            user.save()
            # Create related objects
            personal.objects.get_or_create(user=user)
            income.objects.get_or_create(user=user)
            expenses.objects.get_or_create(user=user)
            savings.objects.get_or_create(user=user)
            assets.objects.get_or_create(user=user)
            financial_goals.objects.get_or_create(user=user)
            risk_profile.objects.get_or_create(user=user)
            login(request, user)
            messages.success(request, 'Registration successful. Please log in.')
            return redirect('landing')  # Redirect to landing page to log in
        else:
            messages.error(request, 'Invalid registration details')

    # Render the form in both GET and POST requests
    return render(request, 'register.html', {'form': form})




@login_required
def financial_profile_view(request):
    step = int(request.GET.get('step', 1))

    if request.method == 'POST':
        if step == 1:
            form = PersonalForm(request.POST, instance=getattr(request.user, 'personal', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=2'
        
        elif step == 2:
            form = IncomeForm(request.POST, instance=getattr(request.user, 'income', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=3'
        
        elif step == 3:
            form = ExpensesForm(request.POST, instance=getattr(request.user, 'expenses', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=4'
        
        elif step == 4:
            form = SavingsForm(request.POST, instance=getattr(request.user, 'savings', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=5'
        
        elif step == 5:
            form = AssetsForm(request.POST, instance=getattr(request.user, 'assets', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=6'
        
        elif step == 6:
            form = FinancialGoalsForm(request.POST, instance=getattr(request.user, 'financial_goals', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=7'
        
        elif step == 7:
            form = RiskProfileForm(request.POST, instance=getattr(request.user, 'risk_profile', None))
            if form.is_valid():
                form.save()
                return redirect('financial_profile_view') + '?step=8'
    
    else:
        # Handle GET request
        forms = {
            'personal_form': PersonalForm(instance=getattr(request.user, 'personal', None)),
            'income_form': IncomeForm(instance=getattr(request.user, 'income', None)),
            'expenses_form': ExpensesForm(instance=getattr(request.user, 'expenses', None)),
            'savings_form': SavingsForm(instance=getattr(request.user, 'savings', None)),
            'assets_form': AssetsForm(instance=getattr(request.user, 'assets', None)),
            'financial_goals_form': FinancialGoalsForm(instance=getattr(request.user, 'financial_goals', None)),
            'risk_profile_form': RiskProfileForm(instance=getattr(request.user, 'risk_profile', None)),
        }

    context = {
        **forms,
        'step': step,
    }

    return render(request, 'data.html', context)



def user_data_form(request):
    if request.method == 'POST':
        form_data = request.POST
        # Process form_data or save it to the database
        print(form_data)  # You can handle the data as needed
        return JsonResponse({'status': 'success'})
    return render(request, 'user_data_form.html')